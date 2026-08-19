"""Provider adapter tests for S3-compatible and Azure Blob object storage."""

# Small fake SDK clients intentionally expose only the methods under test.
# pylint: disable=too-few-public-methods

from datetime import UTC, datetime, timedelta
import hashlib
from io import BytesIO
from types import SimpleNamespace

import pytest

from watchtower_api.config import AzureBlobSettings, ObjectStorageSettings, S3Settings
from watchtower_api.object_storage import (
    AzureBlobObjectStore,
    ObjectIntegrityError,
    S3ObjectStore,
)


TEST_CONTENT = b"x" * 42
TEST_SHA256 = hashlib.sha256(TEST_CONTENT).hexdigest()


def _settings(provider: str = "s3", **overrides) -> ObjectStorageSettings:
    s3 = S3Settings(
        bucket="watchtower-evidence",
        region=overrides.pop("s3_region", "us-gov-west-1"),
        endpoint_url=overrides.pop("s3_endpoint_url", None),
        public_endpoint_url=overrides.pop("s3_public_endpoint_url", None),
        addressing_style=overrides.pop("s3_addressing_style", "auto"),
        server_side_encryption=overrides.pop("s3_server_side_encryption", "AES256"),
        kms_key_id=overrides.pop("s3_kms_key_id", None),
    )
    azure = AzureBlobSettings(
        account_url="https://watchtower.blob.core.usgovcloudapi.net",
        container="evidence",
    )
    return ObjectStorageSettings(
        provider=provider,
        upload_ttl_seconds=900,
        s3=s3,
        azure=azure,
        **overrides,
    )


class FakeS3Client:
    """Capture S3 signing input and return controlled object properties."""

    def __init__(self, content: bytes = TEST_CONTENT) -> None:
        self.presign: dict | None = None
        self.content = content

    def generate_presigned_url(self, operation, **kwargs):
        """Capture presign arguments and return a stable URL."""
        self.presign = {"operation": operation, **kwargs}
        return "https://s3.example.test/signed-upload"

    def head_object(self, **_kwargs):
        """Return provider properties with integrity metadata."""
        return {
            "ContentLength": 42,
            "ContentType": "application/json",
            "Metadata": {"sha256": TEST_SHA256, "expected-size": "42"},
            "ETag": '"test-etag"',
        }

    def get_object(self, **_kwargs):
        """Return the staged bytes for server-side hashing."""
        return {"Body": BytesIO(self.content)}

    def copy_object(self, **_kwargs):
        """Accept preservation of the verified object."""
        return {"CopyObjectResult": {"ETag": '"copied-etag"'}}


@pytest.mark.asyncio
async def test_s3_presign_and_inspection_preserve_integrity_metadata() -> None:
    """S3 URLs sign the properties later required during completion."""
    client = FakeS3Client()
    store = S3ObjectStore(_settings(), client=client)
    expires_at = datetime.now(UTC) + timedelta(minutes=10)

    grant = await store.create_upload(
        "evidence/tenant/upload.json",
        "application/json",
        42,
        TEST_SHA256,
        expires_at,
    )
    stored = await store.finalize_upload(
        "staging/tenant/upload.json",
        "evidence/tenant/upload.json",
        "application/json",
        42,
        TEST_SHA256,
    )

    assert grant.method == "PUT"
    assert grant.headers["x-amz-meta-sha256"] == TEST_SHA256
    assert grant.headers["x-amz-server-side-encryption"] == "AES256"
    assert client.presign["Params"]["Metadata"]["expected-size"] == "42"
    assert client.presign["Params"]["ServerSideEncryption"] == "AES256"
    assert stored.byte_size == 42
    assert stored.sha256 == TEST_SHA256


@pytest.mark.asyncio
async def test_s3_rejects_bytes_that_only_claim_the_expected_hash() -> None:
    """Client-controlled metadata cannot substitute for hashing object bytes."""
    store = S3ObjectStore(_settings(), client=FakeS3Client(content=b"y" * 42))

    with pytest.raises(ObjectIntegrityError):
        await store.finalize_upload(
            "staging/tenant/upload.json",
            "evidence/tenant/upload.json",
            "application/json",
            42,
            TEST_SHA256,
        )


@pytest.mark.parametrize("region", ["us-gov-west-1", "us-gov-east-1"])
def test_s3_uses_govcloud_or_compatible_endpoint_configuration(monkeypatch, region) -> None:
    """GovCloud regions and explicit S3-compatible endpoints use the same adapter."""
    captured = {}

    def fake_client(service, **kwargs):
        captured.update({"service": service, **kwargs})
        return FakeS3Client()

    monkeypatch.setattr("watchtower_api.object_storage.boto3.client", fake_client)
    S3ObjectStore(
        _settings(
            s3_region=region,
            s3_endpoint_url="https://minio.internal.example",
            s3_public_endpoint_url=None,
            s3_addressing_style="path",
        )
    )

    assert captured["service"] == "s3"
    assert captured["region_name"] == region
    assert captured["endpoint_url"] == "https://minio.internal.example"
    assert captured["config"].s3["addressing_style"] == "path"


class FakeBlobClient:
    """Return a stable URL and normalized Azure blob properties."""

    url = "https://watchtower.blob.core.usgovcloudapi.net/evidence/object.json"

    def get_blob_properties(self):
        """Return provider properties with integrity metadata."""
        return SimpleNamespace(
            size=42,
            metadata={"sha256": TEST_SHA256, "expected-size": "42"},
            content_settings=SimpleNamespace(content_type="application/json"),
            etag='"test-etag"',
        )

    def download_blob(self, **_kwargs):
        """Return a chunked downloader over the staged bytes."""
        return SimpleNamespace(chunks=lambda: iter([TEST_CONTENT]))

    def start_copy_from_url(self, *_args, **_kwargs):
        """Accept preservation of the verified blob."""
        return {"copy_status": "success"}


class FakeBlobServiceClient:
    """Minimal Azure service client used without cloud credentials."""

    account_name = "watchtower"

    def get_user_delegation_key(self, **_kwargs):
        """Return a placeholder delegation key consumed by a patched signer."""
        return object()

    def get_blob_client(self, **_kwargs):
        """Return the controlled blob client."""
        return FakeBlobClient()


@pytest.mark.asyncio
async def test_azure_presign_and_inspection_preserve_integrity_metadata(monkeypatch) -> None:
    """Azure SAS uploads carry metadata that completion verifies."""
    monkeypatch.setattr(
        "watchtower_api.object_storage.generate_blob_sas",
        lambda **_kwargs: "signed-sas-token",
    )
    store = AzureBlobObjectStore(
        _settings(provider="azure"),
        service_client=FakeBlobServiceClient(),
    )
    expires_at = datetime.now(UTC) + timedelta(minutes=10)

    grant = await store.create_upload(
        "evidence/tenant/object.json",
        "application/json",
        42,
        TEST_SHA256,
        expires_at,
    )
    stored = await store.finalize_upload(
        "staging/tenant/object.json",
        "evidence/tenant/object.json",
        "application/json",
        42,
        TEST_SHA256,
    )

    assert grant.url.endswith("?signed-sas-token")
    assert grant.headers["x-ms-blob-type"] == "BlockBlob"
    assert grant.headers["x-ms-meta-sha256"] == TEST_SHA256
    assert stored.expected_size == "42"
    assert stored.media_type == "application/json"
