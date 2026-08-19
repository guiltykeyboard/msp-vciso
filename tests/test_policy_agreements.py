"""Version-pinned policy acknowledgement and electronic signature tests."""

from datetime import UTC, datetime, timedelta
import hashlib

from fastapi.testclient import TestClient
import psycopg

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def _approved_policy(client: TestClient, seed_data, title: str = "Acceptable Use Policy"):
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    created = client.post(
        "/v1/policies",
        headers=headers,
        json={
            "title": title,
            "document_type": "policy",
            "content": "Personnel must protect agency information and systems.",
        },
    )
    assert created.status_code == 201
    approved = client.put(
        f"/v1/policies/{created.json()['id']}/status",
        headers=headers,
        json={"status": "approved"},
    )
    assert approved.status_code == 200
    return approved.json()


def _request_agreement(client: TestClient, seed_data, document_id: str, **overrides):
    return client.post(
        f"/v1/policies/{document_id}/agreements",
        headers=_headers(seed_data.organization_a, seed_data.user_a),
        json={
            "recipient_email": "Officer.One@Example.gov",
            "recipient_display_name": "Officer One",
            "expires_in_days": 7,
            **overrides,
        },
    )


def test_policy_agreement_is_hashed_version_pinned_one_time_and_audited(
    seed_data,
    admin_url,
) -> None:
    """A recipient signs one exact version without receiving tenant membership."""
    with TestClient(app) as client:
        policy = _approved_policy(client, seed_data)
        created = _request_agreement(client, seed_data, policy["id"])
        listed = client.get(
            f"/v1/policies/{policy['id']}/agreements",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
        )
        inspected = client.post(
            "/v1/policy-agreements:inspect",
            json={"token": created.json()["token"]},
        )
        acknowledged = client.post(
            "/v1/policy-agreements:acknowledge",
            headers={"User-Agent": "Watchtower agreement test"},
            json={
                "token": created.json()["token"],
                "signer_display_name": "Officer One",
                "agreed": True,
            },
        )
        replay = client.post(
            "/v1/policy-agreements:acknowledge",
            json={
                "token": created.json()["token"],
                "signer_display_name": "Officer One",
                "agreed": True,
            },
        )
        post_signature_inspection = client.post(
            "/v1/policy-agreements:inspect",
            json={"token": created.json()["token"]},
        )

    assert created.status_code == 201
    token_id, secret = created.json()["token"].split(".", 1)
    assert created.json()["recipient_email"] == "officer.one@example.gov"
    assert created.json()["policy_version"] == 1
    assert len(created.json()["document_sha256"]) == 64
    assert listed.status_code == 200
    assert "token" not in listed.json()[0]
    assert inspected.status_code == 200
    assert inspected.json()["document_content"].startswith("Personnel must")
    assert inspected.json()["version_number"] == 1
    assert acknowledged.status_code == 200
    assert acknowledged.json()["signed_version"] == 1
    assert acknowledged.json()["signed_document_sha256"] == created.json()["document_sha256"]
    assert replay.status_code == 401
    assert post_signature_inspection.status_code == 401

    with psycopg.connect(admin_url) as connection:
        request_row = connection.execute(
            """
            select secret_hash, acknowledged_by from policy_agreement_requests
            where public_id = %s
            """,
            (token_id,),
        ).fetchone()
        assert bytes(request_row[0]) == hashlib.sha256(secret.encode()).digest()
        membership = connection.execute(
            """
            select count(*) from organization_memberships
            where organization_id = %s and user_id = %s
            """,
            (seed_data.organization_a, request_row[1]),
        ).fetchone()
        assert membership[0] == 0
        receipt = connection.execute(
            """
            select signer_email, signer_display_name, identity_assurance,
                   user_agent, document_sha256
            from policy_acknowledgements where agreement_request_id = (
              select id from policy_agreement_requests where public_id = %s
            )
            """,
            (token_id,),
        ).fetchone()
        assert receipt[:4] == (
            "officer.one@example.gov",
            "Officer One",
            "email_link",
            "Watchtower agreement test",
        )
        assert receipt[4] == created.json()["document_sha256"]
        events = connection.execute(
            """
            select event_type from audit_events
            where event_type like 'policy.%%' and (
              target_id = %s or details ->> 'agreement_request_id' = %s
            ) order by occurred_at, id
            """,
            (token_id, token_id),
        ).fetchall()
        assert [event[0] for event in events] == [
            "policy.agreement_requested",
            "policy.acknowledged",
        ]
        try:
            connection.execute(
                "update policy_acknowledgements set signer_display_name = 'Changed'"
            )
        except psycopg.errors.ObjectNotInPrerequisiteState:
            connection.rollback()
        else:
            raise AssertionError("Acknowledgement receipts must be immutable")


def test_agreement_requires_approved_document_and_administrator(seed_data) -> None:
    """Drafts cannot be circulated and read-only roles cannot issue signature links."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        draft = client.post(
            "/v1/policies",
            headers=headers,
            json={
                "title": "Draft Procedure",
                "document_type": "procedure",
                "content": "Unapproved procedure.",
            },
        )
        rejected_draft = _request_agreement(client, seed_data, draft.json()["id"])
        policy = _approved_policy(client, seed_data, "Approved Procedure")
        rejected_auditor = client.post(
            f"/v1/policies/{policy['id']}/agreements",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
            json={"recipient_email": "person@example.gov"},
        )

    assert rejected_draft.status_code == 409
    assert rejected_auditor.status_code == 403


def test_agreement_remains_pinned_after_revision_and_is_tenant_isolated(seed_data) -> None:
    """Later policy edits do not rewrite an issued link or expose it to another tenant."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        policy = _approved_policy(client, seed_data)
        agreement = _request_agreement(client, seed_data, policy["id"])
        revision = client.post(
            f"/v1/policies/{policy['id']}/versions",
            headers=headers,
            json={
                "content": "Version two has materially different requirements.",
                "change_summary": "Changed requirements.",
            },
        )
        inspected = client.post(
            "/v1/policy-agreements:inspect",
            json={"token": agreement.json()["token"]},
        )
        foreign_list = client.get(
            f"/v1/policies/{policy['id']}/agreements",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )
        foreign_revoke = client.delete(
            f"/v1/policy-agreements/{agreement.json()['id']}",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )

    assert revision.json()["current_version"] == 2
    assert inspected.json()["version_number"] == 1
    assert "Version two" not in inspected.json()["document_content"]
    assert foreign_list.json() == []
    assert foreign_revoke.status_code == 404


def test_revoked_and_expired_agreement_links_fail_closed(seed_data, admin_url) -> None:
    """Revocation and expiration prevent document inspection and acknowledgement."""
    with TestClient(app) as client:
        policy = _approved_policy(client, seed_data)
        revoked_request = _request_agreement(client, seed_data, policy["id"])
        revoked = client.delete(
            f"/v1/policy-agreements/{revoked_request.json()['id']}",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
        )
        rejected_revoked = client.post(
            "/v1/policy-agreements:inspect",
            json={"token": revoked_request.json()["token"]},
        )
        expired_request = _request_agreement(
            client,
            seed_data,
            policy["id"],
            recipient_email="expired@example.gov",
        )
        with psycopg.connect(admin_url) as connection:
            connection.execute(
                "update policy_agreement_requests set expires_at = %s where public_id = %s",
                (
                    datetime.now(UTC) - timedelta(minutes=1),
                    expired_request.json()["id"],
                ),
            )
            connection.commit()
        rejected_expired = client.post(
            "/v1/policy-agreements:inspect",
            json={"token": expired_request.json()["token"]},
        )

    assert revoked.status_code == 204
    assert rejected_revoked.status_code == 401
    assert rejected_expired.status_code == 401


def test_recurring_agreement_sets_due_date_and_creates_one_successor(
    seed_data,
    admin_url,
) -> None:
    """A completed scheduled cycle can produce one current-version successor."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        policy = _approved_policy(client, seed_data)
        created = _request_agreement(
            client,
            seed_data,
            policy["id"],
            recurrence_days=365,
            prompt_before_days=30,
            schedule_basis="annual-baseline",
        )
        acknowledged = client.post(
            "/v1/policy-agreements:acknowledge",
            json={
                "token": created.json()["token"],
                "signer_display_name": "Officer One",
                "agreed": True,
            },
        )
        with psycopg.connect(admin_url) as connection:
            next_review_at = connection.execute(
                """
                update policy_agreement_requests
                set next_review_at = now()
                where public_id = %s
                returning next_review_at
                """,
                (created.json()["id"],),
            ).fetchone()[0]
            connection.commit()
        renewed = client.post(
            f"/v1/policy-agreements/{created.json()['id']}/renew",
            headers=headers,
        )
        repeated = client.post(
            f"/v1/policy-agreements/{created.json()['id']}/renew",
            headers=headers,
        )
        revoked_successor = client.delete(
            f"/v1/policy-agreements/{renewed.json()['id']}",
            headers=headers,
        )
        reissued = client.post(
            f"/v1/policy-agreements/{created.json()['id']}/renew",
            headers=headers,
        )
        listed = client.get(
            f"/v1/policies/{policy['id']}/agreements",
            headers=headers,
        )

    assert acknowledged.status_code == 200
    assert next_review_at is not None
    assert renewed.status_code == 201
    assert renewed.json()["policy_version"] == 1
    assert renewed.json()["recurrence_days"] == 365
    assert renewed.json()["schedule_basis"] == "annual-baseline"
    assert repeated.status_code == 409
    assert revoked_successor.status_code == 204
    assert reissued.status_code == 201
    assert len(listed.json()) == 3


def test_cadence_suggestions_are_tenant_framework_informed(seed_data, admin_url) -> None:
    """Suggestions cite tenant frameworks without presenting them as mandates."""
    with psycopg.connect(admin_url) as connection:
        connection.execute(
            "update framework_pack_versions set pack_key = 'cjis-security-policy' where id = %s",
            (seed_data.framework_version_id,),
        )
        connection.commit()
    with TestClient(app) as client:
        response = client.get(
            "/v1/policies/agreement-cadence-suggestions",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
        )

    assert response.status_code == 200
    assert [item["key"] for item in response.json()] == [
        "cjis-annual",
        "annual-baseline",
    ]
    assert "does not make every internal policy signature annual" in response.json()[0]["qualification"]
