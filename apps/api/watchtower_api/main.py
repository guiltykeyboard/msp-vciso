"""Watchtower HTTP API."""

from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
from psycopg.types.json import Jsonb

from watchtower_api import __version__
from watchtower_api.config import Settings
from watchtower_api.database import TenantDatabaseSession, create_pool
from watchtower_api.models import (
    AssessmentCreate,
    AssessmentResponse,
    EvidenceObservationCreate,
    EvidenceObservationResponse,
    EvidenceReviewCreate,
    EvidenceReviewResponse,
    OrganizationResponse,
)


ASSESSMENT_CREATORS = frozenset(
    {"customer_admin", "control_owner", "msp_admin", "msp_analyst"}
)
EVIDENCE_SUBMITTERS = ASSESSMENT_CREATORS
EVIDENCE_REVIEWERS = frozenset({"customer_admin", "reviewer", "msp_admin"})

EVIDENCE_SELECT = """
    select
        evidence.public_id as id,
        assessments.public_id as assessment_id,
        evidence.title,
        evidence.description,
        evidence.collection_method,
        evidence.source_type,
        evidence.source_identifier,
        evidence.observed_at,
        evidence.received_at,
        evidence.artifact_name,
        evidence.media_type,
        evidence.byte_size,
        evidence.sha256,
        evidence.sensitivity,
        evidence.normalized_facts,
        evidence.submitted_by,
        latest_review.public_id as review_id,
        latest_review.decision as review_decision,
        latest_review.rationale as review_rationale,
        latest_review.reviewed_by,
        latest_review.reviewed_at
    from evidence_observations as evidence
    join assessments on assessments.id = evidence.assessment_id
    left join lateral (
        select public_id, decision, rationale, reviewed_by, reviewed_at
        from evidence_reviews
        where evidence_observation_id = evidence.id
        order by reviewed_at desc, id desc
        limit 1
    ) as latest_review on true
"""


def _nest_latest_review(row: dict[str, Any]) -> dict[str, Any]:
    """Convert flat SQL review columns into the public nested representation."""
    result = dict(row)
    review_id = result.pop("review_id")
    review_fields = {
        "decision": result.pop("review_decision"),
        "rationale": result.pop("review_rationale"),
        "reviewed_by": result.pop("reviewed_by"),
        "reviewed_at": result.pop("reviewed_at"),
    }
    result["latest_review"] = None if review_id is None else {"id": review_id, **review_fields}
    return result


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
        {
            "name": "evidence",
            "description": "Immutable evidence provenance and human review operations.",
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
            Jsonb({"framework_pack_version_id": payload.framework_pack_version_id}),
        ),
    )
    return assessment


@app.get(
    "/v1/assessments/{assessment_id}/evidence",
    response_model=list[EvidenceObservationResponse],
    tags=["evidence"],
    summary="List assessment evidence",
    operation_id="listAssessmentEvidence",
)
async def list_assessment_evidence(
    assessment_id: UUID,
    session: TenantDatabaseSession,
) -> list[dict[str, Any]]:
    """List evidence and latest reviews for one tenant-visible assessment."""
    cursor = await session.connection.execute(
        EVIDENCE_SELECT
        + """
        where assessments.public_id = %s
        order by evidence.received_at desc, evidence.id desc
        """,
        (assessment_id,),
    )
    rows = await cursor.fetchall()
    if not rows:
        assessment_cursor = await session.connection.execute(
            "select 1 from assessments where public_id = %s",
            (assessment_id,),
        )
        if await assessment_cursor.fetchone() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return [_nest_latest_review(row) for row in rows]


@app.post(
    "/v1/assessments/{assessment_id}/evidence",
    response_model=EvidenceObservationResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["evidence"],
    summary="Register an evidence observation",
    operation_id="createEvidenceObservation",
)
async def create_evidence_observation(
    assessment_id: UUID,
    payload: EvidenceObservationCreate,
    session: TenantDatabaseSession,
) -> Any:
    """Register immutable evidence provenance under an authorized assessment."""
    if session.identity.role not in EVIDENCE_SUBMITTERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot submit evidence",
        )
    assessment_cursor = await session.connection.execute(
        "select id from assessments where public_id = %s",
        (assessment_id,),
    )
    assessment = await assessment_cursor.fetchone()
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    cursor = await session.connection.execute(
        """
        insert into evidence_observations (
            organization_id, assessment_id, title, description, collection_method,
            source_type, source_identifier, observed_at, artifact_name, media_type,
            byte_size, sha256, sensitivity, normalized_facts, submitted_by
        ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        returning public_id
        """,
        (
            session.identity.organization_id,
            assessment["id"],
            payload.title,
            payload.description,
            payload.collection_method,
            payload.source_type,
            payload.source_identifier,
            payload.observed_at,
            payload.artifact_name,
            payload.media_type,
            payload.byte_size,
            payload.sha256,
            payload.sensitivity,
            Jsonb(payload.normalized_facts),
            session.identity.actor_id,
        ),
    )
    evidence_id = (await cursor.fetchone())["public_id"]
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.created', 'evidence_observation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(evidence_id),
            Jsonb({"assessment_id": str(assessment_id), "sha256": payload.sha256}),
        ),
    )
    result_cursor = await session.connection.execute(
        EVIDENCE_SELECT + " where evidence.public_id = %s",
        (evidence_id,),
    )
    return _nest_latest_review(await result_cursor.fetchone())


@app.post(
    "/v1/evidence/{evidence_id}/reviews",
    response_model=EvidenceReviewResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["evidence"],
    summary="Review an evidence observation",
    operation_id="reviewEvidenceObservation",
)
async def review_evidence_observation(
    evidence_id: UUID,
    payload: EvidenceReviewCreate,
    session: TenantDatabaseSession,
) -> Any:
    """Append a human decision without rewriting the evidence or prior reviews."""
    if session.identity.role not in EVIDENCE_REVIEWERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot review evidence",
        )
    evidence_cursor = await session.connection.execute(
        "select id from evidence_observations where public_id = %s",
        (evidence_id,),
    )
    evidence = await evidence_cursor.fetchone()
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    cursor = await session.connection.execute(
        """
        insert into evidence_reviews (
            organization_id, evidence_observation_id, decision, rationale, reviewed_by
        ) values (%s, %s, %s, %s, %s)
        returning public_id as id, decision, rationale, reviewed_by, reviewed_at
        """,
        (
            session.identity.organization_id,
            evidence["id"],
            payload.decision,
            payload.rationale,
            session.identity.actor_id,
        ),
    )
    review = await cursor.fetchone()
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.reviewed', 'evidence_observation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(evidence_id),
            Jsonb({"review_id": str(review["id"]), "decision": payload.decision}),
        ),
    )
    return review
