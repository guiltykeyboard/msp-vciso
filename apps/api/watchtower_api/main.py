"""Watchtower HTTP API."""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, status

from watchtower_api import __version__
from watchtower_api.config import Settings
from watchtower_api.database import TenantDatabaseSession, create_pool
from watchtower_api.models import (
    AssessmentCreate,
    AssessmentResponse,
    OrganizationResponse,
)


ASSESSMENT_CREATORS = frozenset(
    {"customer_admin", "control_owner", "msp_admin", "msp_analyst"}
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Open and close database resources with the application."""
    settings = Settings.from_environment()
    pool = create_pool(settings)
    await pool.open()
    await pool.wait()
    application.state.settings = settings
    application.state.pool = pool
    try:
        yield
    finally:
        await pool.close()


app = FastAPI(
    title="Watchtower GRC API",
    version=__version__,
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
async def liveness() -> dict[str, str]:
    """Return process liveness without touching a dependency."""
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"])
async def readiness() -> dict[str, str]:
    """Return readiness only after PostgreSQL accepts a query."""
    async with app.state.pool.connection() as connection:
        await connection.execute("select 1")
    return {"status": "ready"}


@app.get(
    "/v1/organization",
    response_model=OrganizationResponse,
    tags=["tenancy"],
)
async def current_organization(session: TenantDatabaseSession) -> Any:
    """Return the organization selected by the authorized tenant context."""
    cursor = await session.connection.execute(
        "select id, name, slug from organizations where id = %s",
        (session.identity.organization_id,),
    )
    organization = await cursor.fetchone()
    if organization is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return organization


@app.get(
    "/v1/assessments",
    response_model=list[AssessmentResponse],
    tags=["assessments"],
)
async def list_assessments(session: TenantDatabaseSession) -> list[dict[str, Any]]:
    """List assessments; RLS supplies the mandatory tenant predicate."""
    cursor = await session.connection.execute(
        """
        select public_id as id, name, status, framework_pack_version_id, created_at
        from assessments
        order by created_at desc, id desc
        """
    )
    return await cursor.fetchall()


@app.post(
    "/v1/assessments",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["assessments"],
)
async def create_assessment(
    payload: AssessmentCreate,
    session: TenantDatabaseSession,
) -> Any:
    """Create an assessment inside the active tenant transaction."""
    if session.identity.role not in ASSESSMENT_CREATORS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot create assessments",
        )
    cursor = await session.connection.execute(
        """
        insert into assessments (
            organization_id,
            framework_pack_version_id,
            name,
            created_by
        )
        values (%s, %s, %s, %s)
        returning public_id as id, name, status, framework_pack_version_id, created_at
        """,
        (
            session.identity.organization_id,
            payload.framework_pack_version_id,
            payload.name,
            session.identity.actor_id,
        ),
    )
    assessment = await cursor.fetchone()
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'assessment.created', 'assessment', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(assessment["id"]),
            {"framework_pack_version_id": payload.framework_pack_version_id},
        ),
    )
    return assessment
