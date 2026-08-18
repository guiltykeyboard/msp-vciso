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
    summary="Tenant-safe compliance and evidence automation for MSPs",
    description=(
        "Watchtower's versioned HTTP API for MSP, customer, auditor, evidence, "
        "and assessment workflows. The X-Watchtower headers currently shown on "
        "tenant endpoints are an insecure development adapter, not production authentication."
    ),
    version=__version__,
    lifespan=lifespan,
    contact={
        "name": "Watchtower GRC maintainers",
        "url": "https://github.com/guiltykeyboard/msp-vciso",
    },
    license_info={
        "name": "GNU Affero General Public License v3.0",
        "identifier": "AGPL-3.0-only",
    },
    openapi_tags=[
        {"name": "health", "description": "Process and dependency health checks."},
        {
            "name": "tenancy",
            "description": "The organization authorized for the current request.",
        },
        {
            "name": "assessments",
            "description": "Tenant-isolated compliance assessment operations.",
        },
    ],
)


@app.get(
    "/health/live",
    tags=["health"],
    summary="Check process liveness",
    operation_id="getLiveness",
)
async def liveness() -> dict[str, str]:
    """Return process liveness without touching a dependency."""
    return {"status": "ok"}


@app.get(
    "/health/ready",
    tags=["health"],
    summary="Check database readiness",
    operation_id="getReadiness",
)
async def readiness() -> dict[str, str]:
    """Return readiness only after PostgreSQL accepts a query."""
    async with app.state.pool.connection() as connection:
        await connection.execute("select 1")
    return {"status": "ready"}


@app.get(
    "/v1/organization",
    response_model=OrganizationResponse,
    tags=["tenancy"],
    summary="Get the current organization",
    operation_id="getCurrentOrganization",
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
    summary="List assessments",
    operation_id="listAssessments",
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
    summary="Create an assessment",
    operation_id="createAssessment",
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
