"""Object storage environment validation tests."""

import pytest

from watchtower_api.config import Settings


def test_s3_govcloud_configuration_is_accepted(monkeypatch) -> None:
    """AWS GovCloud regions use the normal S3 provider configuration."""
    monkeypatch.setenv("WATCHTOWER_STORAGE_PROVIDER", "s3")
    monkeypatch.setenv("WATCHTOWER_S3_BUCKET", "watchtower-govcloud-evidence")
    monkeypatch.setenv("WATCHTOWER_S3_REGION", "us-gov-east-1")

    settings = Settings.from_environment()

    assert settings.object_storage.provider == "s3"
    assert settings.object_storage.s3.region == "us-gov-east-1"


def test_production_s3_compatible_endpoint_requires_https(monkeypatch) -> None:
    """Production deployments cannot sign uploads to a plaintext endpoint."""
    monkeypatch.setenv("WATCHTOWER_ENVIRONMENT", "production")
    monkeypatch.setenv("WATCHTOWER_ALLOW_INSECURE_DEV_AUTH", "false")
    monkeypatch.setenv("WATCHTOWER_STORAGE_PROVIDER", "s3")
    monkeypatch.setenv("WATCHTOWER_S3_BUCKET", "watchtower-evidence")
    monkeypatch.setenv("WATCHTOWER_S3_REGION", "us-east-1")
    monkeypatch.setenv("WATCHTOWER_S3_ENDPOINT_URL", "http://minio.internal:9000")

    with pytest.raises(ValueError, match="must use HTTPS"):
        Settings.from_environment()


def test_azure_storage_requires_account_and_container(monkeypatch) -> None:
    """An incomplete Azure configuration is rejected during startup."""
    monkeypatch.setenv("WATCHTOWER_STORAGE_PROVIDER", "azure")
    monkeypatch.delenv("WATCHTOWER_AZURE_STORAGE_ACCOUNT_URL", raising=False)
    monkeypatch.delenv("WATCHTOWER_AZURE_STORAGE_CONTAINER", raising=False)

    with pytest.raises(ValueError, match="Azure storage requires"):
        Settings.from_environment()
