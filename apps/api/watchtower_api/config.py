"""Runtime configuration loaded from environment variables."""

from dataclasses import dataclass
import os


TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
STORAGE_PROVIDERS = frozenset({"disabled", "s3", "azure"})


def _read_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


@dataclass(frozen=True, slots=True)
class S3Settings:
    """Amazon S3 or S3-compatible endpoint configuration."""

    bucket: str | None
    region: str | None
    endpoint_url: str | None
    public_endpoint_url: str | None
    addressing_style: str
    server_side_encryption: str | None
    kms_key_id: str | None


@dataclass(frozen=True, slots=True)
class AzureBlobSettings:
    """Azure Blob account configuration."""

    account_url: str | None
    container: str | None


@dataclass(frozen=True, slots=True)
class ObjectStorageSettings:
    """Provider-neutral object storage configuration."""

    provider: str
    upload_ttl_seconds: int
    s3: S3Settings
    azure: AzureBlobSettings


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated API settings."""

    database_url: str
    environment: str
    allow_insecure_dev_auth: bool
    pool_min_size: int
    pool_max_size: int
    object_storage: ObjectStorageSettings

    @classmethod
    def from_environment(cls) -> "Settings":
        """Build settings and reject development authentication in production."""
        environment = os.getenv("WATCHTOWER_ENVIRONMENT", "development")
        storage = ObjectStorageSettings(
            provider=os.getenv("WATCHTOWER_STORAGE_PROVIDER", "disabled").strip().lower(),
            upload_ttl_seconds=int(os.getenv("WATCHTOWER_UPLOAD_TTL_SECONDS", "900")),
            s3=S3Settings(
                bucket=os.getenv("WATCHTOWER_S3_BUCKET"),
                region=os.getenv("WATCHTOWER_S3_REGION"),
                endpoint_url=os.getenv("WATCHTOWER_S3_ENDPOINT_URL"),
                public_endpoint_url=os.getenv("WATCHTOWER_S3_PUBLIC_ENDPOINT_URL"),
                addressing_style=os.getenv("WATCHTOWER_S3_ADDRESSING_STYLE", "auto"),
                server_side_encryption=os.getenv("WATCHTOWER_S3_SERVER_SIDE_ENCRYPTION"),
                kms_key_id=os.getenv("WATCHTOWER_S3_KMS_KEY_ID"),
            ),
            azure=AzureBlobSettings(
                account_url=os.getenv("WATCHTOWER_AZURE_STORAGE_ACCOUNT_URL"),
                container=os.getenv("WATCHTOWER_AZURE_STORAGE_CONTAINER"),
            ),
        )
        settings = cls(
            database_url=os.getenv(
                "DATABASE_URL",
                "postgresql://watchtower_runtime:watchtower_dev@localhost:5432/watchtower",
            ),
            environment=environment,
            allow_insecure_dev_auth=_read_bool("WATCHTOWER_ALLOW_INSECURE_DEV_AUTH"),
            pool_min_size=int(os.getenv("WATCHTOWER_DB_POOL_MIN_SIZE", "1")),
            pool_max_size=int(os.getenv("WATCHTOWER_DB_POOL_MAX_SIZE", "10")),
            object_storage=storage,
        )
        if settings.environment == "production" and settings.allow_insecure_dev_auth:
            raise ValueError("Insecure development authentication cannot run in production")
        if settings.pool_min_size < 0 or settings.pool_max_size < settings.pool_min_size:
            raise ValueError("Invalid database connection pool limits")
        if storage.provider not in STORAGE_PROVIDERS:
            raise ValueError("WATCHTOWER_STORAGE_PROVIDER must be disabled, s3, or azure")
        if not 60 <= storage.upload_ttl_seconds <= 3600:
            raise ValueError("WATCHTOWER_UPLOAD_TTL_SECONDS must be between 60 and 3600")
        if storage.s3.addressing_style not in {"auto", "path", "virtual"}:
            raise ValueError("WATCHTOWER_S3_ADDRESSING_STYLE must be auto, path, or virtual")
        if storage.provider == "s3" and not (storage.s3.bucket and storage.s3.region):
            raise ValueError("S3 storage requires WATCHTOWER_S3_BUCKET and WATCHTOWER_S3_REGION")
        if storage.s3.kms_key_id and storage.s3.server_side_encryption != "aws:kms":
            raise ValueError("WATCHTOWER_S3_KMS_KEY_ID requires aws:kms server-side encryption")
        if storage.provider == "azure" and not (
            storage.azure.account_url and storage.azure.container
        ):
            raise ValueError(
                "Azure storage requires WATCHTOWER_AZURE_STORAGE_ACCOUNT_URL and "
                "WATCHTOWER_AZURE_STORAGE_CONTAINER"
            )
        if (
            settings.environment == "production"
            and storage.s3.endpoint_url
            and not storage.s3.endpoint_url.startswith("https://")
        ):
            raise ValueError("Production S3-compatible endpoints must use HTTPS")
        if (
            settings.environment == "production"
            and storage.s3.public_endpoint_url
            and not storage.s3.public_endpoint_url.startswith("https://")
        ):
            raise ValueError("Production public S3-compatible endpoints must use HTTPS")
        return settings
