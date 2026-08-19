"""Tenant-scoped client access profiles and one-time invitations."""

from datetime import UTC, datetime, timedelta
import hashlib
import secrets
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, status
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import (
    AuthorizedOrganizationResponse,
    ClientAccessRoleResponse,
    ExternalAuditorInvitationCreate,
    OrganizationInvitationAccept,
    OrganizationInvitationAcceptedResponse,
    OrganizationInvitationCreate,
    OrganizationInvitationCreatedResponse,
    OrganizationInvitationResponse,
)


router = APIRouter()
INVITATION_ADMINS = frozenset({"customer_admin", "msp_admin"})
CLIENT_ACCESS_PROFILES = (
    {
        "id": "customer_admin",
        "name": "Customer administrator",
        "description": "Manages client access and tenant-wide compliance operations.",
        "permissions": [
            "manage_client_access",
            "manage_assessments",
            "submit_evidence",
            "review_evidence",
            "manage_integrations",
            "manage_endpoints",
        ],
    },
    {
        "id": "control_owner",
        "name": "Control owner",
        "description": "Maintains assigned compliance work and submits supporting evidence.",
        "permissions": ["manage_assessments", "submit_evidence", "read_evidence"],
    },
    {
        "id": "reviewer",
        "name": "Evidence reviewer",
        "description": "Reviews submitted evidence without administering tenant access.",
        "permissions": ["review_evidence", "read_evidence"],
    },
    {
        "id": "auditor",
        "name": "External auditor",
        "description": (
            "Views tenant compliance records, evidence, and audit activity without "
            "changes. One auditor identity may hold this role in several invited tenants."
        ),
        "permissions": ["read_assessments", "read_evidence", "read_audit_activity"],
    },
)


def _secret_hash(secret: str) -> bytes:
    """Return the non-reversible representation persisted for an invitation."""
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _require_invitation_admin(session: TenantDatabaseSession) -> None:
    if session.identity.role not in INVITATION_ADMINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot manage client access",
        )


@router.get(
    "/v1/access/roles",
    response_model=list[ClientAccessRoleResponse],
    tags=["client access"],
    summary="List client access profiles",
    operation_id="listClientAccessProfiles",
)
async def list_client_access_profiles(
    session: TenantDatabaseSession,
) -> tuple[dict[str, Any], ...]:
    """Return the auditable role profiles that may be granted to client personnel."""
    del session
    return CLIENT_ACCESS_PROFILES


@router.get(
    "/v1/me/organizations",
    response_model=list[AuthorizedOrganizationResponse],
    tags=["client access"],
    summary="List my authorized organizations",
    operation_id="listCurrentUserOrganizations",
)
async def list_current_user_organizations(
    session: TenantDatabaseSession,
) -> list[dict[str, Any]]:
    """List active tenant memberships for only the current authenticated identity."""
    cursor = await session.connection.execute(
        """
        select organization_id as id,
               organization_name as name,
               organization_slug as slug,
               membership_role as role
        from watchtower_private.current_actor_organizations()
        """
    )
    return await cursor.fetchall()


@router.get(
    "/v1/invitations",
    response_model=list[OrganizationInvitationResponse],
    tags=["client access"],
    summary="List client invitations",
    operation_id="listOrganizationInvitations",
)
async def list_organization_invitations(
    session: TenantDatabaseSession,
) -> list[dict[str, Any]]:
    """List redacted invitation state for the active tenant."""
    _require_invitation_admin(session)
    cursor = await session.connection.execute(
        """
        select public_id as id, email, display_name, role,
               case when status = 'pending' and expires_at <= now()
                    then 'expired' else status end as status,
               expires_at, created_at, accepted_at, revoked_at
        from organization_invitations
        order by created_at desc, id desc
        """
    )
    return await cursor.fetchall()


async def _create_organization_invitation(
    payload: OrganizationInvitationCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Create a one-time tenant invitation after applying shared controls."""
    _require_invitation_admin(session)
    email = payload.email.strip().lower()
    member_cursor = await session.connection.execute(
        "select watchtower_private.organization_has_member_email(%s, %s) as exists",
        (session.identity.organization_id, email),
    )
    if (await member_cursor.fetchone())["exists"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This person already has active access to the organization",
        )

    token_id = uuid4()
    secret = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(days=payload.expires_in_days)
    try:
        cursor = await session.connection.execute(
            """
            insert into organization_invitations (
              public_id, organization_id, email, display_name, role,
              secret_hash, expires_at, invited_by
            ) values (%s, %s, %s, %s, %s, %s, %s, %s)
            returning public_id as id, email, display_name, role, status,
                      expires_at, created_at, accepted_at, revoked_at
            """,
            (
                token_id,
                session.identity.organization_id,
                email,
                payload.display_name,
                payload.role,
                _secret_hash(secret),
                expires_at,
                session.identity.actor_id,
            ),
        )
    except UniqueViolation as conflict:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending invitation already exists for this email address",
        ) from conflict
    invitation = await cursor.fetchone()
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'invitation.created', 'organization_invitation', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(token_id),
            Jsonb({"role": payload.role}),
        ),
    )
    return {**invitation, "token": f"{token_id}.{secret}"}


@router.post(
    "/v1/invitations",
    response_model=OrganizationInvitationCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["client access"],
    summary="Invite client personnel",
    operation_id="createOrganizationInvitation",
)
async def create_organization_invitation(
    payload: OrganizationInvitationCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Create a one-time tenant invitation and return its bearer token once."""
    return await _create_organization_invitation(payload, session)


@router.post(
    "/v1/invitations/external-auditor",
    response_model=OrganizationInvitationCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["client access"],
    summary="Invite an external auditor",
    operation_id="createExternalAuditorInvitation",
)
async def create_external_auditor_invitation(
    payload: ExternalAuditorInvitationCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Invite an external auditor with a non-configurable read-only tenant role."""
    invitation = OrganizationInvitationCreate(
        email=payload.email,
        display_name=payload.display_name,
        role="auditor",
        expires_in_days=payload.expires_in_days,
    )
    return await _create_organization_invitation(invitation, session)


@router.delete(
    "/v1/invitations/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["client access"],
    summary="Revoke a client invitation",
    operation_id="revokeOrganizationInvitation",
)
async def revoke_organization_invitation(
    invitation_id: UUID,
    session: TenantDatabaseSession,
) -> None:
    """Revoke an unconsumed invitation in the active tenant."""
    _require_invitation_admin(session)
    cursor = await session.connection.execute(
        """
        update organization_invitations
        set status = 'revoked', revoked_at = now(), revoked_by = %s
        where public_id = %s and status = 'pending'
        returning public_id
        """,
        (session.identity.actor_id, invitation_id),
    )
    if await cursor.fetchone() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending invitation not found",
        )
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id
        ) values (%s, %s, 'invitation.revoked', 'organization_invitation', %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(invitation_id),
        ),
    )


@router.post(
    "/v1/invitations:accept",
    response_model=OrganizationInvitationAcceptedResponse,
    tags=["client access"],
    summary="Accept a client invitation",
    operation_id="acceptOrganizationInvitation",
)
async def accept_organization_invitation(
    payload: OrganizationInvitationAccept,
    request_context: Request,
) -> dict[str, Any]:
    """Atomically consume a bearer invitation and establish development access."""
    if not request_context.app.state.settings.allow_insecure_dev_auth:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invitation acceptance requires the production identity adapter",
        )
    try:
        token_id_text, secret = payload.token.split(".", 1)
        token_id = UUID(token_id_text)
    except (ValueError, AttributeError) as parse_error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired invitation",
        ) from parse_error

    pool = request_context.app.state.pool
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute(
            "select * from watchtower_private.accept_organization_invitation(%s, %s, %s)",
            (token_id, _secret_hash(secret), payload.display_name.strip()),
        )
        accepted = await cursor.fetchone()
        if accepted is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired invitation",
            )
        await connection.execute(
            "select set_config('watchtower.organization_id', %s, true)",
            (str(accepted["accepted_organization_id"]),),
        )
        organization_cursor = await connection.execute(
            "select name from organizations where id = %s",
            (accepted["accepted_organization_id"],),
        )
        organization = await organization_cursor.fetchone()
        return {
            "organization_id": accepted["accepted_organization_id"],
            "organization_name": organization["name"],
            "actor_id": accepted["accepted_user_id"],
            "role": accepted["accepted_role"],
        }
