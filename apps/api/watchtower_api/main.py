"""Watchtower HTTP API."""

# Route extraction will follow when the application adds its production identity adapter.
# pylint: disable=too-many-lines

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
import re
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, status
from psycopg.types.json import Jsonb

from watchtower_api import __version__
from watchtower_api.access import router as access_router
from watchtower_api.automation import router as automation_router
from watchtower_api.config import Settings
from watchtower_api.database import TenantDatabaseSession, create_pool
from watchtower_api.models import (
    AssessmentCreate,
    AssessmentResponse,
    EvidenceObservationCreate,
    EvidenceObservationResponse,
    EvidenceDownloadResponse,
    EvidenceLegalHoldUpdate,
    EvidenceLifecycleResponse,
    EvidenceRetentionPolicyResponse,
    EvidenceRetentionPolicyUpdate,
    EvidenceReviewCreate,
    EvidenceReviewResponse,
    EvidenceScanResult,
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
from watchtower_api.profile import router as profile_router


ASSESSMENT_CREATORS = frozenset(
    {"customer_admin", "control_owner", "msp_admin", "msp_analyst"}
)
EVIDENCE_SUBMITTERS = ASSESSMENT_CREATORS
EVIDENCE_REVIEWERS = frozenset({"customer_admin", "reviewer", "msp_admin"})
EVIDENCE_LIFECYCLE_ADMINS = frozenset({"customer_admin", "msp_admin"})
EVIDENCE_ARTIFACT_READERS = frozenset(
    {"customer_admin", "control_owner", "reviewer", "auditor", "msp_admin", "msp_analyst"}
)

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
        lifecycle.scan_status,
        lifecycle.scan_engine,
        lifecycle.scan_detail,
        lifecycle.scanned_at,
        lifecycle.retention_until,
        lifecycle.object_lock_mode,
        lifecycle.legal_hold,
        lifecycle.legal_hold_reason,
        lifecycle.updated_at as lifecycle_updated_at,
        latest_review.public_id as review_id,
        latest_review.decision as review_decision,
        latest_review.rationale as review_rationale,
        latest_review.reviewed_by,
        latest_review.reviewed_at
    from evidence_observations as evidence
    join assessments on assessments.id = evidence.assessment_id
    left join evidence_artifact_lifecycle as lifecycle
      on lifecycle.evidence_observation_id = evidence.id
    left join lateral (
        select public_id, decision, rationale, reviewed_by, reviewed_at
        from evidence_reviews
        where evidence_observation_id = evidence.id
        order by reviewed_at desc, id desc
        limit 1
    ) as latest_review on true
"""

LIFECYCLE_SELECT = """
    select scan_status, scan_engine, scan_detail, scanned_at, retention_until,
           object_lock_mode, legal_hold, legal_hold_reason, updated_at
    from evidence_artifact_lifecycle
    where evidence_observation_id = %s
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
    scan_status = result.pop("scan_status")
    lifecycle_fields = {
        "scan_engine": result.pop("scan_engine"),
        "scan_detail": result.pop("scan_detail"),
        "scanned_at": result.pop("scanned_at"),
        "retention_until": result.pop("retention_until"),
        "object_lock_mode": result.pop("object_lock_mode"),
        "legal_hold": result.pop("legal_hold"),
        "legal_hold_reason": result.pop("legal_hold_reason"),
        "updated_at": result.pop("lifecycle_updated_at"),
    }
    result["lifecycle"] = None if scan_status is None else {"scan_status": scan_status, **lifecycle_fields}
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
            "name": "profile",
            "description": "Server-backed preferences for the authenticated user.",
        },
        {
            "name": "client access",
            "description": "Tenant roles and one-time invitations for client personnel.",
        },
        {
            "name": "assessments",
            "description": "Tenant-isolated compliance assessment operations.",
        },
        {
            "name": "evidence",
            "description": "Immutable evidence provenance and human review operations.",
        },
        {"name": "integrations", "description": "Tenant-mapped read-only vendor connections."},
        {"name": "endpoints", "description": "Endpoint collector enrollment and posture ingestion."},
    ],
)
app.include_router(access_router)
app.include_router(automation_router)
app.include_router(profile_router)


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
    policy_cursor = await session.connection.execute(
        "select retention_days, object_lock_mode from evidence_retention_policies where organization_id = %s",
        (session.identity.organization_id,),
    )
    policy = await policy_cursor.fetchone() or {"retention_days": 2555, "object_lock_mode": "none"}
    retention_until = datetime.now(UTC) + timedelta(days=policy["retention_days"])
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
        if policy["object_lock_mode"] != "none":
            await object_store.set_retention(
                final_key,
                retention_until,
                policy["object_lock_mode"],
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
        insert into evidence_artifact_lifecycle (
            organization_id, evidence_observation_id, retention_until,
            object_lock_mode, updated_by
        ) values (%s, %s, %s, %s, %s)
        """,
        (
            session.identity.organization_id,
            evidence["id"],
            retention_until,
            policy["object_lock_mode"],
            session.identity.actor_id,
        ),
    )
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


@app.get(
    "/v1/evidence/{evidence_id}/artifact/download",
    response_model=EvidenceDownloadResponse,
    tags=["evidence"],
    summary="Authorize an evidence artifact download",
    operation_id="createEvidenceDownload",
)
async def create_evidence_download(
    evidence_id: UUID,
    session: TenantDatabaseSession,
) -> Any:
    """Issue a short-lived read URL only after a clean malware scan."""
    if session.identity.role not in EVIDENCE_ARTIFACT_READERS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This tenant role cannot read evidence")
    object_store = _storage_for(app)
    cursor = await session.connection.execute(
        """
        select evidence.id, evidence.artifact_object_key, evidence.storage_provider,
               evidence.sensitivity, lifecycle.scan_status
        from evidence_observations as evidence
        left join evidence_artifact_lifecycle as lifecycle
          on lifecycle.evidence_observation_id = evidence.id
        where evidence.public_id = %s
        """,
        (evidence_id,),
    )
    evidence = await cursor.fetchone()
    if evidence is None or evidence["artifact_object_key"] is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence artifact not found")
    if evidence["storage_provider"] != object_store.provider:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="The artifact storage provider is not active")
    if evidence["scan_status"] != "clean":
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Evidence artifact is unavailable until malware scanning reports it clean",
        )
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    try:
        grant = await object_store.create_download(evidence["artifact_object_key"], expires_at)
    except ObjectStorageError as error:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Object storage could not authorize the download") from error
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.download_authorized', 'evidence_observation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(evidence_id),
            Jsonb({"expires_at": expires_at.isoformat(), "sensitivity": evidence["sensitivity"]}),
        ),
    )
    return {"url": grant.url, "expires_at": grant.expires_at}


@app.post(
    "/v1/evidence/{evidence_id}/scan-result",
    response_model=EvidenceLifecycleResponse,
    tags=["evidence"],
    summary="Record an evidence malware-scan result",
    operation_id="recordEvidenceScanResult",
)
async def record_evidence_scan_result(
    evidence_id: UUID,
    payload: EvidenceScanResult,
    session: TenantDatabaseSession,
) -> Any:
    """Record a scanner result while retaining every transition in the audit ledger."""
    if session.identity.role not in EVIDENCE_LIFECYCLE_ADMINS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This tenant role cannot update scan state")
    evidence_cursor = await session.connection.execute(
        "select id from evidence_observations where public_id = %s",
        (evidence_id,),
    )
    evidence = await evidence_cursor.fetchone()
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    cursor = await session.connection.execute(
        """
        update evidence_artifact_lifecycle
        set scan_status = %s, scan_engine = %s, scan_detail = %s,
            scanned_at = now(), updated_by = %s, updated_at = now()
        where evidence_observation_id = %s
        returning scan_status, scan_engine, scan_detail, scanned_at, retention_until,
                  object_lock_mode, legal_hold, legal_hold_reason, updated_at
        """,
        (payload.status, payload.engine, payload.detail, session.identity.actor_id, evidence["id"]),
    )
    lifecycle = await cursor.fetchone()
    if lifecycle is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Evidence has no stored artifact lifecycle")
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.scan_recorded', 'evidence_observation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(evidence_id),
            Jsonb({"status": payload.status, "engine": payload.engine}),
        ),
    )
    return lifecycle


@app.put(
    "/v1/evidence/{evidence_id}/legal-hold",
    response_model=EvidenceLifecycleResponse,
    tags=["evidence"],
    summary="Set an evidence legal hold",
    operation_id="setEvidenceLegalHold",
)
async def set_evidence_legal_hold(
    evidence_id: UUID,
    payload: EvidenceLegalHoldUpdate,
    session: TenantDatabaseSession,
) -> Any:
    """Set or release a legal hold without deleting or rewriting evidence."""
    if session.identity.role not in EVIDENCE_LIFECYCLE_ADMINS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This tenant role cannot manage legal holds")
    if payload.enabled != bool(payload.reason):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="A reason is required only while legal hold is enabled")
    evidence_cursor = await session.connection.execute(
        "select id from evidence_observations where public_id = %s",
        (evidence_id,),
    )
    evidence = await evidence_cursor.fetchone()
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    cursor = await session.connection.execute(
        """
        update evidence_artifact_lifecycle
        set legal_hold = %s, legal_hold_reason = %s, updated_by = %s, updated_at = now()
        where evidence_observation_id = %s
        returning scan_status, scan_engine, scan_detail, scanned_at, retention_until,
                  object_lock_mode, legal_hold, legal_hold_reason, updated_at
        """,
        (payload.enabled, payload.reason, session.identity.actor_id, evidence["id"]),
    )
    lifecycle = await cursor.fetchone()
    if lifecycle is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Evidence has no stored artifact lifecycle")
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.legal_hold_changed', 'evidence_observation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(evidence_id),
            Jsonb({"enabled": payload.enabled, "reason": payload.reason}),
        ),
    )
    return lifecycle


@app.get(
    "/v1/evidence-retention-policy",
    response_model=EvidenceRetentionPolicyResponse,
    tags=["evidence"],
    summary="Get evidence retention defaults",
    operation_id="getEvidenceRetentionPolicy",
)
async def get_evidence_retention_policy(session: TenantDatabaseSession) -> Any:
    """Return tenant defaults, including safe no-lock behavior when unset."""
    cursor = await session.connection.execute(
        "select retention_days, object_lock_mode, updated_at from evidence_retention_policies where organization_id = %s",
        (session.identity.organization_id,),
    )
    return await cursor.fetchone() or {
        "retention_days": 2555,
        "object_lock_mode": "none",
        "updated_at": datetime.now(UTC),
    }


@app.put(
    "/v1/evidence-retention-policy",
    response_model=EvidenceRetentionPolicyResponse,
    tags=["evidence"],
    summary="Set evidence retention defaults",
    operation_id="setEvidenceRetentionPolicy",
)
async def set_evidence_retention_policy(
    payload: EvidenceRetentionPolicyUpdate,
    session: TenantDatabaseSession,
) -> Any:
    """Set retention defaults for future artifacts; existing holds remain unchanged."""
    if session.identity.role not in EVIDENCE_LIFECYCLE_ADMINS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This tenant role cannot manage retention")
    cursor = await session.connection.execute(
        """
        insert into evidence_retention_policies (
            organization_id, retention_days, object_lock_mode, updated_by
        ) values (%s, %s, %s, %s)
        on conflict (organization_id) do update
        set retention_days = excluded.retention_days,
            object_lock_mode = excluded.object_lock_mode,
            updated_by = excluded.updated_by,
            updated_at = now()
        returning retention_days, object_lock_mode, updated_at
        """,
        (
            session.identity.organization_id,
            payload.retention_days,
            payload.object_lock_mode,
            session.identity.actor_id,
        ),
    )
    policy = await cursor.fetchone()
    await session.connection.execute(
        """
        insert into audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'evidence.retention_policy_changed', 'organization', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(session.identity.organization_id),
            Jsonb(payload.model_dump()),
        ),
    )
    return policy
