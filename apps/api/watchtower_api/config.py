"""Runtime configuration loaded from environment variables."""

from dataclasses import dataclass
import os


TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def _read_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated API settings."""

    database_url: str
    environment: str
    allow_insecure_dev_auth: bool
    pool_min_size: int
    pool_max_size: int

    @classmethod
    def from_environment(cls) -> "Settings":
        """Build settings and reject development authentication in production."""
        settings = cls(
            database_url=os.getenv(
                "DATABASE_URL",
                "postgresql://watchtower_runtime:watchtower_dev@localhost:5432/watchtower",
            ),
            environment=os.getenv("WATCHTOWER_ENVIRONMENT", "development"),
            allow_insecure_dev_auth=_read_bool("WATCHTOWER_ALLOW_INSECURE_DEV_AUTH"),
            pool_min_size=int(os.getenv("WATCHTOWER_DB_POOL_MIN_SIZE", "1")),
            pool_max_size=int(os.getenv("WATCHTOWER_DB_POOL_MAX_SIZE", "10")),
        )
        if settings.environment == "production" and settings.allow_insecure_dev_auth:
            raise ValueError("Insecure development authentication cannot run in production")
        if settings.pool_min_size < 0 or settings.pool_max_size < settings.pool_min_size:
            raise ValueError("Invalid database connection pool limits")
        return settings
