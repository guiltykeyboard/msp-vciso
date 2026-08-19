"""End-to-end direct evidence upload API tests with a controlled object store."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from watchtower_api.main import app
from watchtower_api.object_storage import DownloadGrant, ObjectNotFoundError, StoredObject, UploadGrant


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
        self.downloaded_key: str | None = None
        self.retention: tuple | None = None

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

    async def create_download(self, object_key, expires_at):
        """Return deterministic read authorization."""
        self.downloaded_key = object_key
        return DownloadGrant(url="https://objects.example.test/signed-download", expires_at=expires_at)

    async def set_retention(self, object_key, retain_until, mode):
        """Capture provider-native retention requests."""
        self.retention = (object_key, retain_until, mode)


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


def test_quarantine_scan_download_audit_and_legal_hold(seed_data) -> None:
    """Stored artifacts stay locked until clean and legal-hold changes are audited."""
    store = FakeObjectStore()
    store.stored = StoredObject(
        byte_size=42,
        media_type="application/json",
        sha256="a" * 64,
        expected_size="42",
    )
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        client.app.state.object_store = store
        upload = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence/uploads",
            headers=headers,
            json=_payload(),
        ).json()
        evidence = client.post(
            f"/v1/evidence/uploads/{upload['id']}/complete",
            headers=headers,
        ).json()

        locked = client.get(
            f"/v1/evidence/{evidence['id']}/artifact/download",
            headers=headers,
        )
        scan = client.post(
            f"/v1/evidence/{evidence['id']}/scan-result",
            headers=headers,
            json={"status": "clean", "engine": "fixture-scanner"},
        )
        download = client.get(
            f"/v1/evidence/{evidence['id']}/artifact/download",
            headers=headers,
        )
        hold = client.put(
            f"/v1/evidence/{evidence['id']}/legal-hold",
            headers=headers,
            json={"enabled": True, "reason": "Active records request"},
        )
        cross_tenant = client.get(
            f"/v1/evidence/{evidence['id']}/artifact/download",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )

    assert locked.status_code == 423
    assert scan.status_code == 200
    assert download.status_code == 200
    assert download.json()["url"].endswith("signed-download")
    assert hold.status_code == 200
    assert hold.json()["legal_hold"] is True
    assert cross_tenant.status_code == 404
    assert store.downloaded_key == store.final_key


def test_retention_policy_applies_provider_lock_to_new_artifacts(seed_data) -> None:
    """An explicit tenant policy applies provider retention during completion."""
    store = FakeObjectStore()
    store.stored = StoredObject(42, "application/json", "a" * 64, "42")
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        client.app.state.object_store = store
        policy = client.put(
            "/v1/evidence-retention-policy",
            headers=headers,
            json={"retention_days": 365, "object_lock_mode": "governance"},
        )
        upload = client.post(
            f"/v1/assessments/{seed_data.assessment_a}/evidence/uploads",
            headers=headers,
            json=_payload(),
        ).json()
        completed = client.post(
            f"/v1/evidence/uploads/{upload['id']}/complete",
            headers=headers,
        )

    assert policy.status_code == 200
    assert completed.status_code == 201
    assert store.retention is not None
    assert store.retention[2] == "governance"


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
