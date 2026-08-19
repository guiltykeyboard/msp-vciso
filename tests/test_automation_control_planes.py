"""Microsoft connection and endpoint enrollment control-plane tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def test_microsoft_secret_is_encrypted_and_redacted(seed_data, admin_url, monkeypatch) -> None:
    """Connection responses and database storage never expose the Graph secret."""
    monkeypatch.setenv("WATCHTOWER_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    secret = "a-long-client-secret-value"
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        created = client.post(
            "/v1/integrations/microsoft",
            headers=headers,
            json={
                "display_name": "Northfield GCC",
                "external_tenant_id": str(uuid4()),
                "cloud": "commercial",
                "client_id": str(uuid4()),
                "client_secret": secret,
            },
        )
        listed = client.get("/v1/integrations/microsoft", headers=headers)

    assert created.status_code == 201
    assert secret not in created.text
    assert secret not in listed.text
    import psycopg  # pylint: disable=import-outside-toplevel

    with psycopg.connect(admin_url) as connection:
        encrypted = connection.execute("select encrypted_client_secret from integration_connections").fetchone()[0]
    assert secret.encode() not in bytes(encrypted)


def test_site_token_enrollment_and_idempotent_check_in(seed_data) -> None:
    """A site token is consumed once and the resulting device credential owns check-ins."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    observation_id = uuid4()
    with TestClient(app) as client:
        site = client.post("/v1/sites", headers=headers, json={"name": "HQ"}).json()
        issued = client.post(
            "/v1/agent-enrollment-tokens",
            headers=headers,
            json={
                "site_id": site["id"],
                "allowed_platforms": ["windows", "macos", "linux"],
                "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
                "max_uses": 1,
            },
        )
        enrollment = client.post(
            "/v1/agent-enrollments:exchange",
            json={
                "token": issued.json()["token"],
                "platform": "linux",
                "hostname": "evidence-sensor-1",
                "public_key": "ssh-ed25519 " + "a" * 64,
                "agent_version": "0.1.0",
            },
        )
        replay = client.post(
            "/v1/agent-enrollments:exchange",
            json={
                "token": issued.json()["token"],
                "platform": "linux",
                "hostname": "clone",
                "public_key": "ssh-ed25519 " + "b" * 64,
                "agent_version": "0.1.0",
            },
        )
        enrolled = enrollment.json()
        check_in_payload = {
            "idempotency_key": str(observation_id),
            "schema_version": "v1",
            "observed_at": datetime.now(UTC).isoformat(),
            "facts": {"os": {"family": "linux"}, "disk_encryption": {"enabled": True}},
        }
        check_in = client.post(
            f"/v1/agents/{enrolled['device_id']}/check-ins",
            headers={"Authorization": f"Bearer {enrolled['credential']}"},
            json=check_in_payload,
        )
        repeated = client.post(
            f"/v1/agents/{enrolled['device_id']}/check-ins",
            headers={"Authorization": f"Bearer {enrolled['credential']}"},
            json=check_in_payload,
        )

    assert issued.status_code == 201
    assert enrollment.status_code == 200
    assert replay.status_code == 401
    assert check_in.status_code == 200
    assert repeated.status_code == 200
    assert check_in.json()["received_at"] == repeated.json()["received_at"]
