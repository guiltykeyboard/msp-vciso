"""Watchtower HTTP API."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
import re
from typing import Any
from uuid import UUID, uuid4

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
    EvidenceUploadResponse,
    OrganizationResponse,
)
from watchtower_api.object_storage import (
    ObjectIntegrityError,
    ObjectNotFoundError,
    ObjectStorageError,
    ObjectStore,
    StoredObject,
    create_object_store,
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
        evidence.storage_provider,
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


def _storage_for(application: FastAPI) -> ObjectStore:
    """Return configured storage or fail without exposing provider internals."""
    object_store: ObjectStore | None = application.state.object_store
    if object_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Evidence object storage is not configured",
        )
    return object_store


def _artifact_object_key(
    organization_id: UUID,
    assessment_id: UUID,
    artifact_name: str,
) -> str:
    """Create a non-guessable tenant prefix without trusting a filename as a path."""
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", artifact_name).strip(".-")
    safe_name = (safe_name or "artifact")[-120:]
    return f"evidence/{organization_id}/{assessment_id}/{uuid4().hex}/{safe_name}"


def _object_matches_upload(upload: dict[str, Any], stored: StoredObject) -> bool:
    """Require provider properties to match every integrity claim in the session."""
    return (
        stored.byte_size == upload["byte_size"]
        and stored.expected_size == str(upload["byte_size"])
        and stored.media_type == upload["media_type"]
        and stored.sha256 == upload["sha256"]
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
    application.state.object_store = create_object_store(settings.object_storage)
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


@app.post(
    "/v1/assessments/{assessment_id}/evidence/uploads",
    response_model=EvidenceUploadResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["evidence"],
    summary="Create a direct evidence upload",
    operation_id="createEvidenceUpload",
)
async def create_evidence_upload(
    assessment_id: UUID,
    payload: EvidenceObservationCreate,
    session: TenantDatabaseSession,
) -> Any:
    """Authorize one short-lived upload without proxying artifact bytes."""
    if session.identity.role not in EVIDENCE_SUBMITTERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot submit evidence",
        )
    object_store = _storage_for(app)
    assessment_cursor = await session.connection.execute(
        "select id from assessments where public_id = %s",
        (assessment_id,),
    )
    assessment = await assessment_cursor.fetchone()
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    upload_id = uuid4()
    object_key = _artifact_object_key(
        session.identity.organization_id,
        assessment_id,
        payload.artifact_name,
    ).replace("evidence/", "staging/", 1)
    expires_at = datetime.now(UTC) + timedelta(
        seconds=app.state.settings.object_storage.upload_ttl_seconds
    )
    try:
        grant = await object_store.create_upload(
            object_key,
            payload.media_type,
            payload.byte_size,
            payload.sha256,
            expires_at,
        )
    except ObjectStorageError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Object storage could not authorize the upload",
        ) from error

    await session.connection.execute(
        """
        insert into evidence_upload_sessions (
            public_id, organization_id, assessment_id, provider, object_key,
            title, description, collection_method, source_type, source_identifier,
            observed_at, artifact_name, media_type, byte_size, sha256, sensitivity,
            normalized_facts, created_by, expires_at
        ) values (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """,
        (
            upload_id,
            session.identity.organization_id,
            assessment["id"],
            object_store.provider,
            object_key,
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
            expires_at,
        ),
    )
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.upload_requested', 'evidence_upload', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(upload_id),
            Jsonb({"assessment_id": str(assessment_id), "provider": object_store.provider}),
        ),
    )
    return {
        "id": upload_id,
        "provider": object_store.provider,
        "method": grant.method,
        "url": grant.url,
        "headers": grant.headers,
        "expires_at": grant.expires_at,
    }


@app.post(
    "/v1/evidence/uploads/{upload_id}/complete",
    response_model=EvidenceObservationResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["evidence"],
    summary="Verify and complete an evidence upload",
    operation_id="completeEvidenceUpload",
)
async def complete_evidence_upload(
    upload_id: UUID,
    session: TenantDatabaseSession,
) -> Any:
    """Verify object integrity before committing an immutable observation."""
    if session.identity.role not in EVIDENCE_SUBMITTERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot submit evidence",
        )
    object_store = _storage_for(app)
    cursor = await session.connection.execute(
        """
        select uploads.*, assessments.public_id as assessment_public_id,
               completed.public_id as completed_public_id
        from evidence_upload_sessions as uploads
        join assessments on assessments.id = uploads.assessment_id
        left join evidence_observations as completed on completed.id = uploads.completed_evidence_id
        where uploads.public_id = %s
        for update of uploads
        """,
        (upload_id,),
    )
    upload = await cursor.fetchone()
    if upload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence upload not found")
    if upload["created_by"] != session.identity.actor_id and session.identity.role not in {
        "customer_admin",
        "msp_admin",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot complete another user's upload",
        )
    if upload["status"] == "completed":
        result_cursor = await session.connection.execute(
            EVIDENCE_SELECT + " where evidence.public_id = %s",
            (upload["completed_public_id"],),
        )
        return _nest_latest_review(await result_cursor.fetchone())
    if upload["provider"] != object_store.provider:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The upload's object storage provider is not active",
        )
    if upload["expires_at"] <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Evidence upload authorization has expired",
        )
    try:
        final_key = _artifact_object_key(
            session.identity.organization_id,
            upload["assessment_public_id"],
            upload["artifact_name"],
        )
        stored = await object_store.finalize_upload(
            upload["object_key"],
            final_key,
            upload["media_type"],
            upload["byte_size"],
            upload["sha256"],
        )
    except ObjectNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The uploaded object was not found",
        ) from error
    except ObjectIntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Uploaded object properties do not match the authorized evidence",
        ) from error
    except ObjectStorageError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Object storage could not verify the upload",
        ) from error
    if not _object_matches_upload(upload, stored):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Uploaded object properties do not match the authorized evidence",
        )

    evidence_cursor = await session.connection.execute(
        """
        insert into evidence_observations (
            organization_id, assessment_id, title, description, collection_method,
            source_type, source_identifier, observed_at, artifact_name, media_type,
            byte_size, sha256, sensitivity, normalized_facts, submitted_by,
            storage_provider, artifact_object_key
        ) values (
            %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s
        )
        returning id, public_id
        """,
        (
            session.identity.organization_id,
            upload["assessment_id"],
            upload["title"],
            upload["description"],
            upload["collection_method"],
            upload["source_type"],
            upload["source_identifier"],
            upload["observed_at"],
            upload["artifact_name"],
            upload["media_type"],
            upload["byte_size"],
            upload["sha256"],
            upload["sensitivity"],
            Jsonb(upload["normalized_facts"]),
            upload["created_by"],
            upload["provider"],
            final_key,
        ),
    )
    evidence = await evidence_cursor.fetchone()
    await session.connection.execute(
        """
        update evidence_upload_sessions
        set status = 'completed', completed_evidence_id = %s, completed_at = now()
        where id = %s
        """,
        (evidence["id"], upload["id"]),
    )
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.upload_completed', 'evidence_observation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(evidence["public_id"]),
            Jsonb({"upload_id": str(upload_id), "provider": upload["provider"]}),
        ),
    )
    result_cursor = await session.connection.execute(
        EVIDENCE_SELECT + " where evidence.public_id = %s",
        (evidence["public_id"],),
    )
    return _nest_latest_review(await result_cursor.fetchone())
