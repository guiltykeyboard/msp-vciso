"""Policy/procedure versioning, cross-reference, and tenant-isolation tests."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
import psycopg
from psycopg.types.json import Jsonb

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def _seed_control(admin_url: str, framework_version_id: int) -> None:
    with psycopg.connect(admin_url) as connection:
        connection.execute(
            """
            update framework_pack_versions
            set content = %s
            where id = %s
            """,
            (
                Jsonb(
                    {
                        "requirements": [
                            {
                                "id": "CJIS-5.10.1",
                                "title": "Incident response policy and procedures",
                            }
                        ]
                    }
                ),
                framework_version_id,
            ),
        )
        connection.commit()


def _create_evidence(client: TestClient, seed_data) -> str:
    response = client.post(
        f"/v1/assessments/{seed_data.assessment_a}/evidence",
        headers=_headers(seed_data.organization_a, seed_data.user_a),
        json={
            "title": "Approved incident response plan",
            "collection_method": "manual",
            "source_type": "policy_library_test",
            "observed_at": datetime(2026, 8, 19, 12, 0, tzinfo=UTC).isoformat(),
            "artifact_name": "incident-response-plan.pdf",
            "media_type": "application/pdf",
            "byte_size": 512,
            "sha256": "9" * 64,
            "sensitivity": "confidential",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_policy_versions_controls_evidence_and_lifecycle_are_audited(
    seed_data,
    admin_url,
) -> None:
    """A tenant document retains revisions and validated compliance relationships."""
    _seed_control(admin_url, seed_data.framework_version_id)
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        evidence_id = _create_evidence(client, seed_data)
        options = client.get("/v1/policies/reference-options", headers=headers)
        created = client.post(
            "/v1/policies",
            headers=headers,
            json={
                "title": "Incident Response Policy",
                "document_type": "policy",
                "owner_display_name": "Chief Information Security Officer",
                "review_due_at": "2027-08-19",
                "content": "# Purpose\nDefine the incident response program.",
                "controls": [
                    {
                        "framework_pack_version_id": seed_data.framework_version_id,
                        "control_reference": "CJIS-5.10.1",
                    }
                ],
                "evidence": [
                    {
                        "evidence_id": evidence_id,
                        "relationship": "demonstrates",
                        "notes": "Approved plan substantiates implementation.",
                    }
                ],
            },
        )
        document_id = created.json()["id"]
        revised = client.post(
            f"/v1/policies/{document_id}/versions",
            headers=headers,
            json={
                "content": "# Purpose\nDefine and test the incident response program.",
                "change_summary": "Added annual exercise requirement.",
            },
        )
        approved = client.put(
            f"/v1/policies/{document_id}/status",
            headers=headers,
            json={"status": "approved", "review_due_at": "2027-08-19"},
        )
        listed = client.get("/v1/policies", headers=headers)

    assert options.status_code == 200
    assert options.json()["controls"][0]["reference"] == "CJIS-5.10.1"
    assert options.json()["evidence"][0]["id"] == evidence_id
    assert created.status_code == 201
    assert created.json()["control_count"] == 1
    assert created.json()["evidence_count"] == 1
    assert revised.status_code == 201
    assert revised.json()["current_version"] == 2
    assert [version["version_number"] for version in revised.json()["versions"]] == [2, 1]
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert listed.json()[0]["title"] == "Incident Response Policy"

    with psycopg.connect(admin_url) as connection:
        events = connection.execute(
            """
            select event_type from audit_events
            where target_id = %s order by occurred_at, id
            """,
            (document_id,),
        ).fetchall()
        assert [event[0] for event in events] == [
            "policy.created",
            "policy.revised",
            "policy.status_changed",
        ]
        with connection.transaction():
            version_id = connection.execute(
                """
                select id from policy_document_versions
                where policy_document_id = (
                  select id from policy_documents where public_id = %s
                ) limit 1
                """,
                (document_id,),
            ).fetchone()[0]
        try:
            connection.execute(
                "update policy_document_versions set content = 'rewritten' where id = %s",
                (version_id,),
            )
        except psycopg.errors.ObjectNotInPrerequisiteState:
            connection.rollback()
        else:
            raise AssertionError("Policy revision history must be immutable")


def test_policy_documents_are_tenant_isolated_and_auditors_are_read_only(
    seed_data,
) -> None:
    """A foreign tenant cannot discover a document and an auditor cannot author one."""
    tenant_a = _headers(seed_data.organization_a, seed_data.user_a)
    tenant_b = _headers(seed_data.organization_b, seed_data.user_b)
    auditor = _headers(seed_data.organization_a, seed_data.user_auditor)
    payload = {
        "title": "Acceptable Use Procedure",
        "document_type": "procedure",
        "content": "Personnel must acknowledge acceptable use requirements.",
    }
    with TestClient(app) as client:
        created = client.post("/v1/policies", headers=tenant_a, json=payload)
        document_id = created.json()["id"]
        foreign = client.get(f"/v1/policies/{document_id}", headers=tenant_b)
        auditor_read = client.get(f"/v1/policies/{document_id}", headers=auditor)
        auditor_write = client.post("/v1/policies", headers=auditor, json=payload)

    assert created.status_code == 201
    assert foreign.status_code == 404
    assert auditor_read.status_code == 200
    assert auditor_write.status_code == 403


def test_policy_rejects_foreign_or_unknown_compliance_links(seed_data) -> None:
    """Relationship validation fails closed rather than accepting arbitrary references."""
    with TestClient(app) as client:
        response = client.post(
            "/v1/policies",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
            json={
                "title": "Invalid crosswalk",
                "document_type": "policy",
                "content": "This record must not be stored.",
                "controls": [
                    {
                        "framework_pack_version_id": seed_data.framework_version_id,
                        "control_reference": "UNKNOWN-CONTROL",
                    }
                ],
            },
        )

    assert response.status_code == 422
