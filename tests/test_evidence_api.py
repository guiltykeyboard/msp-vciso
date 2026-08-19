"""Evidence provenance, review, authorization, and tenant-isolation tests."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def _evidence_payload(title: str = "Disk encryption report") -> dict:
    return {
        "title": title,
        "description": "Export captured from the endpoint management console.",
        "collection_method": "manual",
        "source_type": "endpoint_management",
        "source_identifier": "device-123",
        "observed_at": datetime(2026, 8, 18, 12, 0, tzinfo=UTC).isoformat(),
        "artifact_name": "disk-encryption.json",
        "media_type": "application/json",
        "byte_size": 128,
        "sha256": "b" * 64,
        "sensitivity": "security_record",
        "normalized_facts": {"disk_encrypted": True},
    }


def test_submit_review_and_list_evidence(seed_data) -> None:
    """A permitted tenant user can register evidence and append a review."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        create_response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=headers,
            json=_evidence_payload(),
        )
        assert create_response.status_code == 201
        evidence = create_response.json()
        assert evidence["assessment_id"] == str(seed_data.assessment_a)
        assert evidence["sha256"] == "b" * 64
        assert evidence["latest_review"] is None

        review_response = client.post(
            f"/v1/evidence/{evidence['id']}/reviews",
            headers=headers,
            json={"decision": "accepted", "rationale": "Artifact matches the scoped device."},
        )
        assert review_response.status_code == 201
        assert review_response.json()["decision"] == "accepted"

        list_response = client.get(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=headers,
        )

    assert list_response.status_code == 200
    listed_evidence = next(item for item in list_response.json() if item["id"] == evidence["id"])
    assert listed_evidence["latest_review"]["decision"] == "accepted"
    assert listed_evidence["normalized_facts"] == {"disk_encrypted": True}


def test_auditor_cannot_submit_or_review_evidence(seed_data) -> None:
    """Read-only auditors cannot add observations or review decisions."""
    auditor_headers = _headers(seed_data.organization_a, seed_data.user_auditor)
    admin_headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        create_response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=auditor_headers,
            json=_evidence_payload("Forbidden auditor evidence"),
        )
        assert create_response.status_code == 403

        evidence_response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=admin_headers,
            json=_evidence_payload("Review role test"),
        )
        review_response = client.post(
            f"/v1/evidence/{evidence_response.json()['id']}/reviews",
            headers=auditor_headers,
            json={"decision": "accepted", "rationale": "Forbidden"},
        )

    assert review_response.status_code == 403


def test_cross_tenant_evidence_is_not_disclosed(seed_data) -> None:
    """A neighboring tenant receives not-found responses for foreign records."""
    tenant_a_headers = _headers(seed_data.organization_a, seed_data.user_a)
    tenant_b_headers = _headers(seed_data.organization_b, seed_data.user_b)
    with TestClient(app) as client:
        evidence_response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=tenant_a_headers,
            json=_evidence_payload("Tenant A private evidence"),
        )
        evidence_id = evidence_response.json()["id"]

        list_response = client.get(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=tenant_b_headers,
        )
        review_response = client.post(
            f"/v1/evidence/{evidence_id}/reviews",
            headers=tenant_b_headers,
            json={"decision": "accepted", "rationale": "Cross-tenant attempt"},
        )

    assert list_response.status_code == 404
    assert review_response.status_code == 404


def test_evidence_hash_must_be_canonical_sha256(seed_data) -> None:
    """Malformed or uppercase hashes are rejected before database insertion."""
    payload = _evidence_payload()
    payload["sha256"] = "NOT-A-SHA256"
    with TestClient(app) as client:
        response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
            json=payload,
        )

    assert response.status_code == 422


def test_evidence_observed_time_requires_timezone(seed_data) -> None:
    """Evidence timestamps cannot depend on an implicit server timezone."""
    payload = _evidence_payload()
    payload["observed_at"] = "2026-08-18T12:00:00"
    with TestClient(app) as client:
        response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
            json=payload,
        )

    assert response.status_code == 422
