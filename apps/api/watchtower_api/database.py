"""Database pool and tenant-scoped transaction dependencies."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from psycopg import AsyncConnection, sql
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from watchtower_api.config import Settings


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    """Identity and tenant authorization established for one request."""

    organization_id: UUID
    actor_id: UUID
    role: str


@dataclass(slots=True)
class TenantSession:
    """An open transaction with tenant context already applied."""

    connection: AsyncConnection
    identity: TenantIdentity


def create_pool(settings: Settings) -> AsyncConnectionPool:
    """Create a closed pool so the application lifespan controls startup."""
    return AsyncConnectionPool(
        conninfo=settings.database_url,
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        open=False,
        kwargs={"autocommit": False, "row_factory": dict_row},
    )


async def tenant_session(
    request: Request,
    organization_id: Annotated[UUID, Header(alias="X-Watchtower-Organization")],
    actor_id: Annotated[UUID, Header(alias="X-Watchtower-Actor")],
) -> AsyncIterator[TenantSession]:
    """Authorize development identity and apply transaction-local RLS context."""
    settings: Settings = request.app.state.settings
    if not settings.allow_insecure_dev_auth:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No production identity adapter is configured",
        )

    pool: AsyncConnectionPool = request.app.state.pool
    async with pool.connection() as connection:
        async with connection.transaction():
            await connection.execute(
                "select set_config('watchtower.organization_id', %s, true)",
                (str(organization_id),),
            )
            await connection.execute(
                "select set_config('watchtower.actor_id', %s, true)",
                (str(actor_id),),
            )
            cursor = await connection.execute(
                sql.SQL(
                    """
                    select role
                    from organization_memberships
                    where organization_id = %s
                      and user_id = %s
                      and status = 'active'
                    """
                ),
                (organization_id, actor_id),
            )
            membership = await cursor.fetchone()
            if membership is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No active membership for this organization",
                )
            yield TenantSession(
                connection=connection,
                identity=TenantIdentity(
                    organization_id=organization_id,
                    actor_id=actor_id,
                    role=membership["role"],
                ),
            )


TenantDatabaseSession = Annotated[TenantSession, Depends(tenant_session)]
