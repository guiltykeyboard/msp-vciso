"""Recipient-scoped policy acknowledgement and electronic signature routes."""

from datetime import UTC, datetime, timedelta
import hashlib
import ipaddress
import secrets
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, status
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import (
    PolicyAcknowledgementReceiptResponse,
    PolicyAgreementAcknowledge,
    PolicyAgreementCadenceSuggestion,
    PolicyAgreementCreate,
    PolicyAgreementCreatedResponse,
    PolicyAgreementInspectionResponse,
    PolicyAgreementResponse,
    PolicyAgreementTokenRequest,
)


router = APIRouter()
AGREEMENT_ADMINS = frozenset({"customer_admin", "msp_admin"})
ATTESTATION_TEXT = "I have read this document and agree to follow its requirements."
CADENCE_SUGGESTIONS = {
    "cjis": {
        "key": "cjis-annual",
        "label": "Annual CJIS-aligned review",
        "recurrence_days": 365,
        "prompt_before_days": 30,
        "rationale": "Align acknowledgement review with annual CJIS security and privacy literacy training, and issue a new request sooner when the document changes.",
        "source_label": "FBI CJIS Security Policy 6.1, AT-2",
        "source_url": "https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625.pdf/view",
        "qualification": "AT-2 requires annual literacy training; it does not make every internal policy signature annual. Confirm the applicable CSA and local overlay.",
    },
    "ohio": {
        "key": "ohio-annual",
        "label": "Annual Ohio cybersecurity review",
        "recurrence_days": 365,
        "prompt_before_days": 30,
        "rationale": "Align policy acknowledgement review with the political subdivision's role-appropriate cybersecurity training cycle.",
        "source_label": "Ohio Revised Code 9.64(C)(6)",
        "source_url": "https://codes.ohio.gov/ohio-revised-code/section-9.64",
        "qualification": "The statute recognizes annual state training but does not expressly require annual signatures. The legislative authority sets the program details.",
    },
}
DEFAULT_SUGGESTION = {
    "key": "annual-baseline",
    "label": "Annual review baseline",
    "recurrence_days": 365,
    "prompt_before_days": 30,
    "rationale": "Use an annual acknowledgement review as a configurable governance baseline and reissue immediately after material policy changes.",
    "source_label": "Organization-defined baseline",
    "source_url": "https://pages.nist.gov/oscal-tools/demos/csx/baseline-reviewer/",
    "qualification": "NIST SP 800-53 PS-6 leaves the re-signing frequency organization-defined. Counsel, contracts, and sector overlays may require a different cadence.",
}


def _secret_hash(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _parse_token(token: str) -> tuple[UUID, bytes]:
    try:
        token_id_text, secret = token.split(".", 1)
        if len(secret) < 32:
            raise ValueError("secret is too short")
        return UUID(token_id_text), _secret_hash(secret)
    except (ValueError, AttributeError) as parse_error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired policy agreement",
        ) from parse_error


def _require_agreement_admin(session: TenantDatabaseSession) -> None:
    if session.identity.role not in AGREEMENT_ADMINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot manage policy agreements",
        )


def _require_development_identity_adapter(request: Request) -> None:
    """Fail closed until production recipient identity verification is available."""
    if not request.app.state.settings.allow_insecure_dev_auth:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Policy acknowledgement requires the production identity adapter",
        )


def _connection_ip(request: Request) -> str | None:
    """Record only a syntactically valid direct peer address, not proxy headers."""
    if request.client is None:
        return None
    try:
        return str(ipaddress.ip_address(request.client.host))
    except ValueError:
        return None


@router.get(
    "/v1/policies/{document_id}/agreements",
    response_model=list[PolicyAgreementResponse],
    tags=["policy agreements"],
    summary="List policy acknowledgement requests",
    operation_id="listPolicyAgreements",
)
async def list_policy_agreements(
    document_id: UUID,
    session: TenantDatabaseSession,
) -> list[dict[str, Any]]:
    """List redacted recipient status for one tenant document."""
    _require_agreement_admin(session)
    cursor = await session.connection.execute(
        """
        select requests.public_id as id, documents.public_id as policy_document_id,
               versions.version_number as policy_version,
               requests.recipient_email, requests.recipient_display_name,
               requests.document_sha256,
               case when requests.status = 'pending' and requests.expires_at <= now()
                    then 'expired' else requests.status end as status,
               requests.expires_at, requests.created_at, requests.acknowledged_at,
               requests.revoked_at, receipts.signer_display_name,
               receipts.identity_assurance, requests.recurrence_days,
               requests.prompt_before_days, requests.next_review_at,
               requests.schedule_basis,
               (requests.status = 'acknowledged'
                and requests.recurrence_days is not null
                and requests.superseded_by_request_id is null
                and requests.next_review_at - make_interval(days => requests.prompt_before_days) <= now()
               ) as renewal_available
        from policy_agreement_requests requests
        join policy_documents documents on documents.id = requests.policy_document_id
        join policy_document_versions versions
          on versions.id = requests.policy_document_version_id
        left join policy_acknowledgements receipts
          on receipts.agreement_request_id = requests.id
        where documents.public_id = %s
        order by requests.created_at desc, requests.id desc
        """,
        (document_id,),
    )
    return await cursor.fetchall()


@router.get(
    "/v1/policies/agreement-cadence-suggestions",
    response_model=list[PolicyAgreementCadenceSuggestion],
    tags=["policy agreements"],
    summary="Suggest policy acknowledgement review cadences",
    operation_id="listPolicyAgreementCadenceSuggestions",
)
async def list_cadence_suggestions(
    session: TenantDatabaseSession,
) -> list[dict[str, Any]]:
    """Return source-labeled advisory cadences for assessed tenant frameworks."""
    _require_agreement_admin(session)
    rows = await (
        await session.connection.execute(
            """
            select distinct lower(frameworks.pack_key) as pack_key
            from assessments
            join framework_pack_versions frameworks
              on frameworks.id = assessments.framework_pack_version_id
            where assessments.status <> 'archived'
            """
        )
    ).fetchall()
    suggestions: list[dict[str, Any]] = []
    for row in rows:
        pack_key = row["pack_key"]
        for marker, suggestion in CADENCE_SUGGESTIONS.items():
            if marker in pack_key and suggestion not in suggestions:
                suggestions.append(suggestion)
    suggestions.append(DEFAULT_SUGGESTION)
    return suggestions


@router.post(
    "/v1/policies/{document_id}/agreements",
    response_model=PolicyAgreementCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["policy agreements"],
    summary="Request a policy acknowledgement",
    operation_id="createPolicyAgreement",
)
async def create_policy_agreement(
    document_id: UUID,
    payload: PolicyAgreementCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Pin an approved version to one recipient and return its secret once."""
    _require_agreement_admin(session)
    if payload.recurrence_days is None and payload.prompt_before_days != 14:
        raise HTTPException(status_code=422, detail="A prompt lead time requires a recurring review")
    if payload.recurrence_days is not None and payload.prompt_before_days >= payload.recurrence_days:
        raise HTTPException(status_code=422, detail="Prompt lead time must be shorter than the review cadence")
    document = await (
        await session.connection.execute(
            """
            select documents.id, documents.public_id, documents.status,
                   documents.current_version, versions.id as version_id,
                   versions.content
            from policy_documents documents
            join policy_document_versions versions
              on versions.policy_document_id = documents.id
             and versions.version_number = documents.current_version
            where documents.public_id = %s
            """,
            (document_id,),
        )
    ).fetchone()
    if document is None:
        raise HTTPException(status_code=404, detail="Policy document not found")
    if document["status"] != "approved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only an approved policy version can be sent for acknowledgement",
        )

    token_id = uuid4()
    secret = secrets.token_urlsafe(32)
    recipient_email = payload.recipient_email.strip().lower()
    expires_at = datetime.now(UTC) + timedelta(days=payload.expires_in_days)
    document_sha256 = hashlib.sha256(document["content"].encode("utf-8")).hexdigest()
    try:
        request_row = await (
            await session.connection.execute(
                """
                insert into policy_agreement_requests (
                  public_id, organization_id, policy_document_id,
                  policy_document_version_id, recipient_email,
                  recipient_display_name, secret_hash, document_sha256,
                  attestation_text, requested_by, expires_at, recurrence_days,
                  prompt_before_days, schedule_basis
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning public_id as id, recipient_email, recipient_display_name,
                          document_sha256, status, expires_at, created_at,
                          acknowledged_at, revoked_at, recurrence_days,
                          prompt_before_days, next_review_at, schedule_basis
                """,
                (
                    token_id,
                    session.identity.organization_id,
                    document["id"],
                    document["version_id"],
                    recipient_email,
                    payload.recipient_display_name,
                    _secret_hash(secret),
                    document_sha256,
                    ATTESTATION_TEXT,
                    session.identity.actor_id,
                    expires_at,
                    payload.recurrence_days,
                    payload.prompt_before_days,
                    payload.schedule_basis,
                ),
            )
        ).fetchone()
    except UniqueViolation as conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending acknowledgement already exists for this recipient and version",
        ) from conflict

    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'policy.agreement_requested', 'policy_agreement_request', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(token_id),
            Jsonb(
                {
                    "policy_document_id": str(document_id),
                    "version": document["current_version"],
                    "document_sha256": document_sha256,
                }
            ),
        ),
    )
    return {
        **request_row,
        "policy_document_id": document["public_id"],
        "policy_version": document["current_version"],
        "signer_display_name": None,
        "identity_assurance": None,
        "renewal_available": False,
        "token": f"{token_id}.{secret}",
    }


@router.delete(
    "/v1/policy-agreements/{agreement_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["policy agreements"],
    summary="Revoke a policy acknowledgement request",
    operation_id="revokePolicyAgreement",
)
async def revoke_policy_agreement(
    agreement_id: UUID,
    session: TenantDatabaseSession,
) -> None:
    """Revoke a still-pending recipient link under tenant RLS."""
    _require_agreement_admin(session)
    result = await session.connection.execute(
        """
        update policy_agreement_requests
        set status = 'revoked', revoked_at = now(), revoked_by = %s
        where public_id = %s and status = 'pending'
        returning id, public_id
        """,
        (session.identity.actor_id, agreement_id),
    )
    revoked_request = await result.fetchone()
    if revoked_request is None:
        raise HTTPException(status_code=404, detail="Pending policy agreement not found")
    await session.connection.execute(
        """
        update policy_agreement_requests
        set superseded_by_request_id = null
        where superseded_by_request_id = %s
        """,
        (revoked_request["id"],),
    )
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id
        ) values (%s, %s, 'policy.agreement_revoked', 'policy_agreement_request', %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(agreement_id),
        ),
    )


@router.post(
    "/v1/policy-agreements/{agreement_id}/renew",
    response_model=PolicyAgreementCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["policy agreements"],
    summary="Create the next scheduled policy review",
    operation_id="renewPolicyAgreement",
)
async def renew_policy_agreement(
    agreement_id: UUID,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Create one due successor pinned to the document's current approved version."""
    _require_agreement_admin(session)
    source = await (
        await session.connection.execute(
            """
            select requests.id, requests.organization_id,
                   requests.policy_document_id, requests.recipient_email,
                   requests.recipient_display_name, requests.recurrence_days,
                   requests.prompt_before_days, requests.schedule_basis,
                   documents.public_id as policy_document_public_id,
                   documents.status as policy_status,
                   documents.current_version, versions.id as version_id,
                   versions.content
            from policy_agreement_requests requests
            join policy_documents documents on documents.id = requests.policy_document_id
            join policy_document_versions versions
              on versions.policy_document_id = documents.id
             and versions.version_number = documents.current_version
            where requests.public_id = %s
              and requests.status = 'acknowledged'
              and requests.recurrence_days is not null
              and requests.superseded_by_request_id is null
              and requests.next_review_at - make_interval(days => requests.prompt_before_days) <= now()
            """,
            (agreement_id,),
        )
    ).fetchone()
    if source is None:
        raise HTTPException(status_code=409, detail="This recurring agreement is not due for renewal")
    if source["policy_status"] != "approved":
        raise HTTPException(status_code=409, detail="Approve the current policy before renewing")

    token_id = uuid4()
    secret = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(days=30)
    document_sha256 = hashlib.sha256(source["content"].encode("utf-8")).hexdigest()
    try:
        successor = await (
            await session.connection.execute(
                """
                insert into policy_agreement_requests (
                  public_id, organization_id, policy_document_id,
                  policy_document_version_id, recipient_email,
                  recipient_display_name, secret_hash, document_sha256,
                  attestation_text, requested_by, expires_at, recurrence_days,
                  prompt_before_days, schedule_basis
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id as database_id, public_id as id, recipient_email, recipient_display_name,
                          document_sha256, status, expires_at, created_at,
                          acknowledged_at, revoked_at, recurrence_days,
                          prompt_before_days, next_review_at, schedule_basis
                """,
                (
                    token_id,
                    source["organization_id"],
                    source["policy_document_id"],
                    source["version_id"],
                    source["recipient_email"],
                    source["recipient_display_name"],
                    _secret_hash(secret),
                    document_sha256,
                    ATTESTATION_TEXT,
                    session.identity.actor_id,
                    expires_at,
                    source["recurrence_days"],
                    source["prompt_before_days"],
                    source["schedule_basis"],
                ),
            )
        ).fetchone()
        updated = await session.connection.execute(
            """
            update policy_agreement_requests
            set superseded_by_request_id = %s
            where id = %s and superseded_by_request_id is null
            returning id
            """,
            (successor["database_id"], source["id"]),
        )
        if await updated.fetchone() is None:
            raise HTTPException(status_code=409, detail="A renewal was already created")
    except UniqueViolation as conflict:
        raise HTTPException(status_code=409, detail="A renewal already exists for this recipient") from conflict

    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'policy.agreement_renewed', 'policy_agreement_request', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(token_id),
            Jsonb({"predecessor_request_id": str(agreement_id), "version": source["current_version"]}),
        ),
    )
    return {
        **successor,
        "policy_document_id": source["policy_document_public_id"],
        "policy_version": source["current_version"],
        "signer_display_name": None,
        "identity_assurance": None,
        "renewal_available": False,
        "token": f"{token_id}.{secret}",
    }


@router.post(
    "/v1/policy-agreements:inspect",
    response_model=PolicyAgreementInspectionResponse,
    tags=["policy agreements"],
    summary="Inspect a recipient policy agreement",
    operation_id="inspectPolicyAgreement",
)
async def inspect_policy_agreement(
    payload: PolicyAgreementTokenRequest,
    request: Request,
) -> dict[str, Any]:
    """Resolve only the exact version authorized by a recipient-specific link."""
    _require_development_identity_adapter(request)
    token_id, presented_hash = _parse_token(payload.token)
    async with request.app.state.pool.connection() as connection:
        row = await (
            await connection.execute(
                "select * from watchtower_private.inspect_policy_agreement(%s, %s)",
                (token_id, presented_hash),
            )
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired policy agreement",
        )
    return row


@router.post(
    "/v1/policy-agreements:acknowledge",
    response_model=PolicyAcknowledgementReceiptResponse,
    tags=["policy agreements"],
    summary="Electronically acknowledge a policy",
    operation_id="acknowledgePolicyAgreement",
)
async def acknowledge_policy_agreement(
    payload: PolicyAgreementAcknowledge,
    request: Request,
) -> dict[str, Any]:
    """Atomically consume the link and create an immutable signed receipt."""
    _require_development_identity_adapter(request)
    token_id, presented_hash = _parse_token(payload.token)
    client_ip = _connection_ip(request)
    user_agent = request.headers.get("user-agent", "")[:1000]
    async with request.app.state.pool.connection() as connection, connection.transaction():
        row = await (
            await connection.execute(
                """
                select * from watchtower_private.acknowledge_policy_agreement(
                  %s, %s, %s, %s, %s
                )
                """,
                (
                    token_id,
                    presented_hash,
                    payload.signer_display_name.strip(),
                    client_ip,
                    user_agent,
                ),
            )
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or already acknowledged policy agreement",
        )
    return row
