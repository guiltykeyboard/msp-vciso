"""End-to-end direct evidence upload API tests with a controlled object store."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from watchtower_api.main import app
from watchtower_api.object_storage import ObjectNotFoundError, StoredObject, UploadGrant


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def _payload(artifact_name: str = "report.json") -> dict:
    return {
        "title": "Endpoint encryption report",
        "description": "Direct-upload API test",
        "collection_method": "manual",
        "source_type": "endpoint_management",
        "source_identifier": "device-123",
        "observed_at": datetime(2026, 8, 18, 12, 0, tzinfo=UTC).isoformat(),
        "artifact_name": artifact_name,
        "media_type": "application/json",
        "byte_size": 42,
        "sha256": "a" * 64,
        "sensitivity": "security_record",
        "normalized_facts": {"disk_encrypted": True},
    }


class FakeObjectStore:
    """Record authorization and expose an object only when the test uploads it."""

    provider = "s3"

    def __init__(self) -> None:
        self.object_key: str | None = None
        self.final_key: str | None = None
        self.stored: StoredObject | None = None

    async def create_upload(self, object_key, media_type, byte_size, sha256, expires_at):
        """Capture the object key and return deterministic upload instructions."""
        self.object_key = object_key
        return UploadGrant(
            method="PUT",
            url="https://objects.example.test/signed-upload",
            headers={
                "Content-Type": media_type,
                "x-amz-meta-sha256": sha256,
                "x-amz-meta-expected-size": str(byte_size),
            },
            expires_at=expires_at,
        )

    async def finalize_upload(
        self,
        staging_key,
        final_key,
        _media_type,
        _byte_size,
        _sha256,
    ):
        """Return the object only after the test marks it uploaded."""
        assert staging_key == self.object_key
        self.final_key = final_key
        if self.stored is None:
            raise ObjectNotFoundError
        return self.stored


def test_direct_upload_is_verified_and_completed_idempotently(seed_data) -> None:
    """Only matching object properties become one immutable observation."""
    store = FakeObjectStore()
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        client.app.state.object_store = store
        create_response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence/uploads",
            headers=headers,
            json=_payload("../reports/encryption.json"),
        )
        assert create_response.status_code == 201
        upload = create_response.json()
        assert upload["provider"] == "s3"
        assert upload["method"] == "PUT"
        assert upload["headers"]["x-amz-meta-sha256"] == "a" * 64
        assert store.object_key.startswith(
            f"staging/{seed_data.organization_a}/{seed_data.assessment_a}/"
        )
        assert ".." not in store.object_key

        missing_response = client.post(
            f"/v1/evidence/uploads/{upload['id']}/complete",
            headers=headers,
        )
        assert missing_response.status_code == 409

        store.stored = StoredObject(
            byte_size=42,
            media_type="application/json",
            sha256="a" * 64,
            expected_size="42",
        )
        complete_response = client.post(
            f"/v1/evidence/uploads/{upload['id']}/complete",
            headers=headers,
        )
        repeated_response = client.post(
            f"/v1/evidence/uploads/{upload['id']}/complete",
            headers=headers,
        )

    assert complete_response.status_code == 201
    assert complete_response.json()["storage_provider"] == "s3"
    assert complete_response.json()["sha256"] == "a" * 64
    assert repeated_response.status_code == 201
    assert repeated_response.json()["id"] == complete_response.json()["id"]
    assert store.final_key.startswith(
        f"evidence/{seed_data.organization_a}/{seed_data.assessment_a}/"
    )


def test_upload_property_mismatch_and_cross_tenant_access_are_rejected(seed_data) -> None:
    """Wrong object properties and neighboring tenants cannot complete an upload."""
    store = FakeObjectStore()
    tenant_a_headers = _headers(seed_data.organization_a, seed_data.user_a)
    tenant_b_headers = _headers(seed_data.organization_b, seed_data.user_b)
    with TestClient(app) as client:
        client.app.state.object_store = store
        create_response = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence/uploads",
            headers=tenant_a_headers,
            json=_payload(),
        )
        upload_id = create_response.json()["id"]
        store.stored = StoredObject(
            byte_size=41,
            media_type="application/json",
            sha256="a" * 64,
            expected_size="42",
        )

        mismatch_response = client.post(
            f"/v1/evidence/uploads/{upload_id}/complete",
            headers=tenant_a_headers,
        )
        cross_tenant_response = client.post(
            f"/v1/evidence/uploads/{upload_id}/complete",
            headers=tenant_b_headers,
        )

    assert mismatch_response.status_code == 409
    assert cross_tenant_response.status_code == 404
