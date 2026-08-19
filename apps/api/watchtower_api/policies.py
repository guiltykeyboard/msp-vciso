"""Tenant policy and procedure library routes."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from psycopg.types.json import Jsonb

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import (
    PolicyDocumentCreate,
    PolicyDocumentResponse,
    PolicyDocumentStatusUpdate,
    PolicyDocumentSummaryResponse,
    PolicyDocumentVersionCreate,
    PolicyReferenceOptionsResponse,
)


router = APIRouter()
POLICY_EDITORS = frozenset(
    {"customer_admin", "control_owner", "msp_admin", "msp_analyst"}
)
POLICY_APPROVERS = frozenset({"customer_admin", "msp_admin"})


def _require_role(session: TenantDatabaseSession, allowed: frozenset[str]) -> None:
    if session.identity.role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot modify policies and procedures",
        )


async def _document_row(
    document_id: UUID,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    cursor = await session.connection.execute(
        """
        select documents.id as internal_id, documents.public_id as id,
               documents.title, documents.document_type, documents.status,
               documents.owner_display_name, documents.review_due_at,
               documents.current_version, documents.updated_at,
               count(distinct controls.id)::integer as control_count,
               count(distinct evidence.id)::integer as evidence_count
        from policy_documents as documents
        left join policy_control_links as controls
          on controls.policy_document_id = documents.id
        left join policy_evidence_links as evidence
          on evidence.policy_document_id = documents.id
        where documents.public_id = %s
        group by documents.id
        """,
        (document_id,),
    )
    document = await cursor.fetchone()
    if document is None:
        raise HTTPException(status_code=404, detail="Policy document not found")
    return document


async def _document_detail(
    document_id: UUID,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    document = await _document_row(document_id, session)
    internal_id = document.pop("internal_id")
    versions = await (
        await session.connection.execute(
            """
            select public_id as id, version_number, content, change_summary,
                   authored_by, created_at
            from policy_document_versions
            where policy_document_id = %s
            order by version_number desc
            """,
            (internal_id,),
        )
    ).fetchall()
    controls = await (
        await session.connection.execute(
            """
            select links.framework_pack_version_id,
                   packs.pack_key || ' ' || packs.version as framework,
                   links.control_reference, links.control_title, links.linked_at
            from policy_control_links as links
            join framework_pack_versions as packs
              on packs.id = links.framework_pack_version_id
            where links.policy_document_id = %s
            order by links.control_reference
            """,
            (internal_id,),
        )
    ).fetchall()
    evidence = await (
        await session.connection.execute(
            """
            select observations.public_id as evidence_id,
                   observations.title as evidence_title,
                   links.relationship, links.notes, links.linked_at
            from policy_evidence_links as links
            join evidence_observations as observations
              on observations.id = links.evidence_observation_id
            where links.policy_document_id = %s
            order by observations.title, observations.public_id
            """,
            (internal_id,),
        )
    ).fetchall()
    return {**document, "versions": versions, "controls": controls, "evidence": evidence}


async def _control_catalog(session: TenantDatabaseSession) -> list[dict[str, Any]]:
    packs = await (
        await session.connection.execute(
            """
            select distinct packs.id, packs.pack_key, packs.version, packs.content
            from framework_pack_versions as packs
            join assessments on assessments.framework_pack_version_id = packs.id
            order by packs.pack_key, packs.version, packs.id
            """
        )
    ).fetchall()
    controls: list[dict[str, Any]] = []
    for pack in packs:
        framework = f"{pack['pack_key']} {pack['version']}"
        for requirement in pack["content"].get("requirements", []):
            reference = requirement.get("id")
            title = requirement.get("title")
            if isinstance(reference, str) and isinstance(title, str):
                controls.append(
                    {
                        "framework_pack_version_id": pack["id"],
                        "framework": framework,
                        "reference": reference,
                        "title": title,
                    }
                )
    return controls


@router.get(
    "/v1/policies/reference-options",
    response_model=PolicyReferenceOptionsResponse,
    tags=["policies"],
    summary="List policy cross-reference options",
    operation_id="listPolicyReferenceOptions",
)
async def list_policy_reference_options(
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Return only controls and evidence already visible in the active tenant."""
    evidence = await (
        await session.connection.execute(
            """
            select observations.public_id as id, observations.title,
                   assessments.name as assessment_name,
                   observations.sensitivity, observations.observed_at
            from evidence_observations as observations
            join assessments on assessments.id = observations.assessment_id
            order by observations.received_at desc, observations.id desc
            limit 200
            """
        )
    ).fetchall()
    return {"controls": await _control_catalog(session), "evidence": evidence}


@router.get(
    "/v1/policies",
    response_model=list[PolicyDocumentSummaryResponse],
    tags=["policies"],
    summary="List policies and procedures",
    operation_id="listPolicyDocuments",
)
async def list_policy_documents(
    session: TenantDatabaseSession,
) -> list[dict[str, Any]]:
    """List tenant documents with their control and evidence coverage."""
    cursor = await session.connection.execute(
        """
        select documents.public_id as id, documents.title,
               documents.document_type, documents.status,
               documents.owner_display_name, documents.review_due_at,
               documents.current_version, documents.updated_at,
               count(distinct controls.id)::integer as control_count,
               count(distinct evidence.id)::integer as evidence_count
        from policy_documents as documents
        left join policy_control_links as controls
          on controls.policy_document_id = documents.id
        left join policy_evidence_links as evidence
          on evidence.policy_document_id = documents.id
        group by documents.id
        order by documents.updated_at desc, documents.id desc
        """
    )
    return await cursor.fetchall()


@router.post(
    "/v1/policies",
    response_model=PolicyDocumentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["policies"],
    summary="Create a policy or procedure",
    operation_id="createPolicyDocument",
)
async def create_policy_document(
    payload: PolicyDocumentCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Create a draft with an immutable first revision and validated links."""
    _require_role(session, POLICY_EDITORS)
    catalog = {
        (item["framework_pack_version_id"], item["reference"]): item
        for item in await _control_catalog(session)
    }
    requested_controls = {
        (item.framework_pack_version_id, item.control_reference)
        for item in payload.controls
    }
    if len(requested_controls) != len(payload.controls) or not requested_controls.issubset(catalog):
        raise HTTPException(status_code=422, detail="One or more control references are invalid")

    evidence_rows: dict[UUID, dict[str, Any]] = {}
    requested_evidence = {item.evidence_id for item in payload.evidence}
    if len(requested_evidence) != len(payload.evidence):
        raise HTTPException(status_code=422, detail="Evidence links must be unique")
    if requested_evidence:
        cursor = await session.connection.execute(
            """
            select id, public_id from evidence_observations
            where public_id = any(%s)
            """,
            (list(requested_evidence),),
        )
        evidence_evidence_rows = await cursor.fetchall()
        evidence_rows = {row["public_id"]: row for row in evidence_evidence_rows}
        if requested_evidence != set(evidence_rows):
            raise HTTPException(status_code=422, detail="One or more evidence links are invalid")

    document = await (
        await session.connection.execute(
            """
            insert into policy_documents (
              organization_id, title, document_type, owner_display_name,
              review_due_at, created_by
            ) values (%s, %s, %s, %s, %s, %s)
            returning id, public_id
            """,
            (
                session.identity.organization_id,
                payload.title,
                payload.document_type,
                payload.owner_display_name,
                payload.review_due_at,
                session.identity.actor_id,
            ),
        )
    ).fetchone()
    await session.connection.execute(
        """
        insert into policy_document_versions (
          organization_id, policy_document_id, version_number, content,
          change_summary, authored_by
        ) values (%s, %s, 1, %s, %s, %s)
        """,
        (
            session.identity.organization_id,
            document["id"],
            payload.content,
            payload.change_summary,
            session.identity.actor_id,
        ),
    )
    for pack_id, reference in sorted(requested_controls):
        item = catalog[(pack_id, reference)]
        await session.connection.execute(
            """
            insert into policy_control_links (
              organization_id, policy_document_id, framework_pack_version_id,
              control_reference, control_title, linked_by
            ) values (%s, %s, %s, %s, %s, %s)
            """,
            (
                session.identity.organization_id,
                document["id"],
                pack_id,
                reference,
                item["title"],
                session.identity.actor_id,
            ),
        )
    for link in payload.evidence:
        await session.connection.execute(
            """
            insert into policy_evidence_links (
              organization_id, policy_document_id, evidence_observation_id,
              relationship, notes, linked_by
            ) values (%s, %s, %s, %s, %s, %s)
            """,
            (
                session.identity.organization_id,
                document["id"],
                evidence_rows[link.evidence_id]["id"],
                link.relationship,
                link.notes,
                session.identity.actor_id,
            ),
        )
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'policy.created', 'policy_document', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(document["public_id"]),
            Jsonb(
                {
                    "document_type": payload.document_type,
                    "control_count": len(payload.controls),
                    "evidence_count": len(payload.evidence),
                }
            ),
        ),
    )
    return await _document_detail(document["public_id"], session)


@router.get(
    "/v1/policies/{document_id}",
    response_model=PolicyDocumentResponse,
    tags=["policies"],
    summary="Get a policy or procedure",
    operation_id="getPolicyDocument",
)
async def get_policy_document(
    document_id: UUID,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Return the tenant document, all revisions, controls, and evidence links."""
    return await _document_detail(document_id, session)


@router.post(
    "/v1/policies/{document_id}/versions",
    response_model=PolicyDocumentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["policies"],
    summary="Create a policy revision",
    operation_id="createPolicyDocumentVersion",
)
async def create_policy_document_version(
    document_id: UUID,
    payload: PolicyDocumentVersionCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Append a revision without overwriting the historical document body."""
    _require_role(session, POLICY_EDITORS)
    cursor = await session.connection.execute(
        """
        select id, current_version from policy_documents
        where public_id = %s for update
        """,
        (document_id,),
    )
    document = await cursor.fetchone()
    if document is None:
        raise HTTPException(status_code=404, detail="Policy document not found")
    next_version = document["current_version"] + 1
    await session.connection.execute(
        """
        insert into policy_document_versions (
          organization_id, policy_document_id, version_number, content,
          change_summary, authored_by
        ) values (%s, %s, %s, %s, %s, %s)
        """,
        (
            session.identity.organization_id,
            document["id"],
            next_version,
            payload.content,
            payload.change_summary,
            session.identity.actor_id,
        ),
    )
    await session.connection.execute(
        """
        update policy_documents
        set current_version = %s, status = 'draft', updated_at = now()
        where id = %s
        """,
        (next_version, document["id"]),
    )
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'policy.revised', 'policy_document', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(document_id),
            Jsonb({"version": next_version, "change_summary": payload.change_summary}),
        ),
    )
    return await _document_detail(document_id, session)


@router.put(
    "/v1/policies/{document_id}/status",
    response_model=PolicyDocumentResponse,
    tags=["policies"],
    summary="Set policy lifecycle status",
    operation_id="setPolicyDocumentStatus",
)
async def set_policy_document_status(
    document_id: UUID,
    payload: PolicyDocumentStatusUpdate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Record an administrator's approval, draft, or retirement decision."""
    _require_role(session, POLICY_APPROVERS)
    result = await session.connection.execute(
        """
        update policy_documents
        set status = %s, review_due_at = %s, updated_at = now()
        where public_id = %s
        returning public_id, current_version
        """,
        (payload.status, payload.review_due_at, document_id),
    )
    updated_document = await result.fetchone()
    if updated_document is None:
        raise HTTPException(status_code=404, detail="Policy document not found")
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'policy.status_changed', 'policy_document', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(document_id),
            Jsonb(
                {
                    "status": payload.status,
                    "version": updated_document["current_version"],
                    "review_due_at": (
                        payload.review_due_at.isoformat()
                        if payload.review_due_at is not None
                        else None
                    ),
                }
            ),
        ),
    )
    return await _document_detail(document_id, session)
