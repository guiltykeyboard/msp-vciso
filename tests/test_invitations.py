"""Tenant invitation and client access profile tests."""

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


def _create_invitation(client: TestClient, seed_data, **overrides):
    payload = {
        "email": "New.Person@Example.gov",
        "display_name": "New Person",
        "role": "control_owner",
        "expires_in_days": 7,
        **overrides,
    }
    return client.post(
        "/v1/invitations",
        headers=_headers(seed_data.organization_a, seed_data.user_a),
        json=payload,
    )


def test_access_profiles_are_documented_for_tenant_members(seed_data) -> None:
    """Every member can understand the fixed profiles an administrator may grant."""
    with TestClient(app) as client:
        response = client.get(
            "/v1/access/roles",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
        )

    assert response.status_code == 200
    assert [profile["id"] for profile in response.json()] == [
        "customer_admin",
        "control_owner",
        "reviewer",
        "auditor",
    ]
    assert all(profile["permissions"] for profile in response.json())


def test_admin_creates_and_lists_redacted_invitation(seed_data, admin_url) -> None:
    """An administrator receives the bearer token once while storage keeps only its hash."""
    with TestClient(app) as client:
        created = _create_invitation(client, seed_data)
        listed = client.get(
            "/v1/invitations",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
        )

    assert created.status_code == 201
    token_id, secret = created.json()["token"].split(".", 1)
    assert created.json()["email"] == "new.person@example.gov"
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == token_id
    assert "token" not in listed.json()[0]

    with psycopg.connect(admin_url) as connection:
        invitation = connection.execute(
            "select secret_hash from organization_invitations where public_id = %s",
            (token_id,),
        ).fetchone()
        assert bytes(invitation[0]) == hashlib.sha256(secret.encode()).digest()
        event = connection.execute(
            "select details from audit_events where event_type = 'invitation.created' and target_id = %s",
            (token_id,),
        ).fetchone()
        assert event[0] == {"role": "control_owner"}


def test_non_admin_cannot_manage_invitations(seed_data) -> None:
    """Read-only and work roles cannot escalate tenant access."""
    with TestClient(app) as client:
        response = client.post(
            "/v1/invitations",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
            json={"email": "person@example.gov", "role": "auditor"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "This tenant role cannot manage client access"


def test_invitation_acceptance_creates_membership_and_is_one_time(seed_data, admin_url) -> None:
    """Acceptance atomically provisions one tenant membership and consumes the secret."""
    with TestClient(app) as client:
        created = _create_invitation(
            client,
            seed_data,
            email="reviewer@example.gov",
            role="reviewer",
        )
        accepted = client.post(
            "/v1/invitations:accept",
            json={"token": created.json()["token"], "display_name": "Jamie Reviewer"},
        )
        replay = client.post(
            "/v1/invitations:accept",
            json={"token": created.json()["token"], "display_name": "Jamie Reviewer"},
        )
        dashboard = client.get(
            "/v1/dashboard",
            headers=_headers(accepted.json()["organization_id"], accepted.json()["actor_id"]),
        )

    assert accepted.status_code == 200
    assert accepted.json()["role"] == "reviewer"
    assert accepted.json()["organization_name"] == "Tenant A"
    assert replay.status_code == 401
    assert dashboard.status_code == 200
    assert dashboard.json()["identity"]["role"] == "reviewer"

    with psycopg.connect(admin_url) as connection:
        membership = connection.execute(
            "select role, status from organization_memberships where organization_id = %s and user_id = %s",
            (accepted.json()["organization_id"], accepted.json()["actor_id"]),
        ).fetchone()
        assert membership == ("reviewer", "active")
        event = connection.execute(
            "select details from audit_events where event_type = 'invitation.accepted' and target_id = %s",
            (created.json()["id"],),
        ).fetchone()
        assert event[0] == {"role": "reviewer"}


def test_revoked_and_expired_invitations_cannot_be_accepted(seed_data, admin_url) -> None:
    """Revocation and expiration independently invalidate bearer invitations."""
    with TestClient(app) as client:
        revoked_invite = _create_invitation(client, seed_data, email="revoked@example.gov")
        revoked = client.delete(
            f"/v1/invitations/{revoked_invite.json()['id']}",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
        )
        rejected_revoked = client.post(
            "/v1/invitations:accept",
            json={"token": revoked_invite.json()["token"], "display_name": "Revoked Person"},
        )
        expired_invite = _create_invitation(client, seed_data, email="expired@example.gov")
        with psycopg.connect(admin_url) as connection:
            connection.execute(
                "update organization_invitations set expires_at = %s where public_id = %s",
                (datetime.now(UTC) - timedelta(minutes=1), expired_invite.json()["id"]),
            )
            connection.commit()
        rejected_expired = client.post(
            "/v1/invitations:accept",
            json={"token": expired_invite.json()["token"], "display_name": "Expired Person"},
        )

    assert revoked.status_code == 204
    assert rejected_revoked.status_code == 401
    assert rejected_expired.status_code == 401


def test_pending_invitation_is_unique_and_tenant_isolated(seed_data) -> None:
    """Duplicate and neighboring-tenant operations reveal no invitation secret or state."""
    with TestClient(app) as client:
        created = _create_invitation(client, seed_data, email="isolated@example.gov")
        duplicate = _create_invitation(client, seed_data, email="isolated@example.gov")
        cross_tenant_revoke = client.delete(
            f"/v1/invitations/{created.json()['id']}",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )
        tenant_b_list = client.get(
            "/v1/invitations",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )

    assert duplicate.status_code == 409
    assert cross_tenant_revoke.status_code == 404
    assert tenant_b_list.json() == []


def test_existing_member_and_msp_roles_cannot_be_invited(seed_data, admin_url) -> None:
    """Invitations cannot silently rewrite active access or grant an MSP identity."""
    with psycopg.connect(admin_url) as connection:
        connection.execute(
            "update app_users set email = 'member@example.gov' where id = %s",
            (seed_data.user_auditor,),
        )
        connection.commit()
    with TestClient(app) as client:
        member = _create_invitation(client, seed_data, email="member@example.gov")
        msp_role = _create_invitation(
            client,
            seed_data,
            email="not-msp@example.gov",
            role="msp_admin",
        )

    assert member.status_code == 409
    assert msp_role.status_code == 422
