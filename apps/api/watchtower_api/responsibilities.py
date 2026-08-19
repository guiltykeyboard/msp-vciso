"""Tenant organizational roles and shared-responsibility matrix routes."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from psycopg.errors import ForeignKeyViolation, UniqueViolation
from psycopg.types.json import Jsonb

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import (
    ResponsibilityAssignmentCreate,
    ResponsibilityAssignmentResponse,
    ResponsibilityHolderCreate,
    ResponsibilityHolderResponse,
    ResponsibilityMatrixResponse,
    ResponsibilityRoleCreate,
    ResponsibilityRoleResponse,
)


router = APIRouter()
RESPONSIBILITY_ADMINS = frozenset({"customer_admin", "msp_admin"})


def _require_admin(session: TenantDatabaseSession) -> None:
    if session.identity.role not in RESPONSIBILITY_ADMINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This tenant role cannot manage organizational responsibilities",
        )


async def _control_catalog(session: TenantDatabaseSession) -> list[dict[str, Any]]:
    rows = await (
        await session.connection.execute(
            """
            select distinct packs.id, packs.pack_key, packs.version, packs.content
            from framework_pack_versions packs
            join assessments on assessments.framework_pack_version_id = packs.id
            where assessments.status <> 'archived'
            order by packs.pack_key, packs.version, packs.id
            """
        )
    ).fetchall()
    controls: list[dict[str, Any]] = []
    for row in rows:
        framework = f"{row['pack_key']} {row['version']}"
        for requirement in row["content"].get("requirements", []):
            reference = requirement.get("id")
            title = requirement.get("title")
            if isinstance(reference, str) and isinstance(title, str):
                controls.append(
                    {
                        "framework_pack_version_id": row["id"],
                        "framework": framework,
                        "reference": reference,
                        "title": title,
                    }
                )
    return controls


async def _options(session: TenantDatabaseSession) -> dict[str, Any]:
    policies = await (
        await session.connection.execute(
            """
            select public_id as id, title, document_type, status, current_version
            from policy_documents
            where status <> 'retired'
            order by title, id
            """
        )
    ).fetchall()
    return {"policies": policies, "controls": await _control_catalog(session)}


async def _roles(session: TenantDatabaseSession) -> list[dict[str, Any]]:
    roles = await (
        await session.connection.execute(
            """
            select public_id as id, id as internal_id, name, description, party,
                   status, created_at
            from responsibility_roles
            order by status, name, id
            """
        )
    ).fetchall()
    holders = await (
        await session.connection.execute(
            """
            select holders.public_id as id, roles.public_id as role_id,
                   holders.app_user_id, holders.display_name, holders.email,
                   holders.is_primary, holders.starts_on, holders.ends_on,
                   holders.created_at
            from responsibility_role_holders holders
            join responsibility_roles roles on roles.id = holders.responsibility_role_id
            order by holders.ends_on nulls first, holders.is_primary desc,
                     holders.display_name, holders.id
            """
        )
    ).fetchall()
    by_role: dict[UUID, list[dict[str, Any]]] = {}
    for holder in holders:
        by_role.setdefault(holder.pop("role_id"), []).append(holder)
    return [
        {**{key: value for key, value in role.items() if key != "internal_id"}, "holders": by_role.get(role["id"], [])}
        for role in roles
    ]


async def _assignments(session: TenantDatabaseSession) -> list[dict[str, Any]]:
    rows = await (
        await session.connection.execute(
            """
            select assignments.public_id as id, roles.public_id as role_id,
                   roles.name as role_name, roles.party as role_party,
                   assignments.target_type, policies.public_id as policy_id,
                   policies.title as policy_title,
                   assignments.framework_pack_version_id,
                   assignments.control_reference, packs.pack_key, packs.version,
                   assignments.raci, assignments.delivery_model,
                   assignments.notes, assignments.assigned_at
            from responsibility_assignments assignments
            join responsibility_roles roles on roles.id = assignments.responsibility_role_id
            left join policy_documents policies on policies.id = assignments.policy_document_id
            left join framework_pack_versions packs
              on packs.id = assignments.framework_pack_version_id
            order by coalesce(policies.title, assignments.control_reference),
                     assignments.raci, roles.name
            """
        )
    ).fetchall()
    control_titles = {
        (item["framework_pack_version_id"], item["reference"]): item["title"]
        for item in await _control_catalog(session)
    }
    resolved: list[dict[str, Any]] = []
    for row in rows:
        if row["target_type"] == "policy":
            target_key = str(row["policy_id"])
            target_title = row["policy_title"]
            framework = None
        else:
            target_key = f"{row['framework_pack_version_id']}:{row['control_reference']}"
            target_title = control_titles.get(
                (row["framework_pack_version_id"], row["control_reference"]),
                row["control_reference"],
            )
            framework = f"{row['pack_key']} {row['version']}"
        resolved.append(
            {
                "id": row["id"],
                "role_id": row["role_id"],
                "role_name": row["role_name"],
                "role_party": row["role_party"],
                "target_type": row["target_type"],
                "target_key": target_key,
                "target_title": target_title,
                "framework": framework,
                "raci": row["raci"],
                "delivery_model": row["delivery_model"],
                "notes": row["notes"],
                "assigned_at": row["assigned_at"],
            }
        )
    return resolved


@router.get(
    "/v1/responsibilities",
    response_model=ResponsibilityMatrixResponse,
    tags=["responsibilities"],
    summary="Get the tenant responsibility matrix",
    operation_id="getResponsibilityMatrix",
)
async def get_responsibility_matrix(
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Return roles, holders, RACI rows, and tenant-valid mapping targets."""
    return {
        "roles": await _roles(session),
        "assignments": await _assignments(session),
        "options": await _options(session),
    }


@router.post(
    "/v1/responsibility-roles",
    response_model=ResponsibilityRoleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["responsibilities"],
    summary="Create an organizational responsibility role",
    operation_id="createResponsibilityRole",
)
async def create_responsibility_role(
    payload: ResponsibilityRoleCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Create a responsibility role without granting application permissions."""
    _require_admin(session)
    try:
        row = await (
            await session.connection.execute(
                """
                insert into responsibility_roles (
                  organization_id, name, description, party, created_by
                ) values (%s, %s, %s, %s, %s)
                returning public_id as id, name, description, party, status, created_at
                """,
                (
                    session.identity.organization_id,
                    payload.name.strip(),
                    payload.description,
                    payload.party,
                    session.identity.actor_id,
                ),
            )
        ).fetchone()
    except UniqueViolation as conflict:
        raise HTTPException(status_code=409, detail="An organizational role with this name already exists") from conflict
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'responsibility.role_created', 'responsibility_role', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(row["id"]),
            Jsonb({"party": payload.party}),
        ),
    )
    return {**row, "holders": []}


@router.post(
    "/v1/responsibility-roles/{role_id}/holders",
    response_model=ResponsibilityHolderResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["responsibilities"],
    summary="Assign a person to an organizational role",
    operation_id="createResponsibilityHolder",
)
async def create_responsibility_holder(
    role_id: UUID,
    payload: ResponsibilityHolderCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Name a role holder without implicitly granting tenant access."""
    _require_admin(session)
    role = await (
        await session.connection.execute(
            "select id, public_id from responsibility_roles where public_id = %s and status = 'active'",
            (role_id,),
        )
    ).fetchone()
    if role is None:
        raise HTTPException(status_code=404, detail="Organizational role not found")
    email = payload.email.lower() if payload.email else None
    try:
        holder = await (
            await session.connection.execute(
                """
                insert into responsibility_role_holders (
                  organization_id, responsibility_role_id, app_user_id,
                  display_name, email, is_primary, starts_on, ends_on, created_by
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning public_id as id, app_user_id, display_name, email,
                          is_primary, starts_on, ends_on, created_at
                """,
                (
                    session.identity.organization_id,
                    role["id"],
                    None,
                    payload.display_name.strip(),
                    email,
                    payload.is_primary,
                    payload.starts_on,
                    payload.ends_on,
                    session.identity.actor_id,
                ),
            )
        ).fetchone()
    except UniqueViolation as conflict:
        raise HTTPException(status_code=409, detail="This role already has a current primary holder") from conflict
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'responsibility.holder_assigned', 'responsibility_role', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(role_id),
            Jsonb({"holder_id": str(holder["id"]), "is_primary": payload.is_primary}),
        ),
    )
    return holder


@router.post(
    "/v1/responsibility-assignments",
    response_model=ResponsibilityAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["responsibilities"],
    summary="Map a role to a policy or control",
    operation_id="createResponsibilityAssignment",
)
async def create_responsibility_assignment(
    payload: ResponsibilityAssignmentCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Create one RACI row with an explicit service-delivery boundary."""
    _require_admin(session)
    role = await (
        await session.connection.execute(
            "select id, public_id, name, party from responsibility_roles where public_id = %s and status = 'active'",
            (payload.role_id,),
        )
    ).fetchone()
    if role is None:
        raise HTTPException(status_code=404, detail="Organizational role not found")

    policy_internal_id = None
    framework = None
    if payload.target_type == "policy":
        if payload.policy_document_id is None or payload.framework_pack_version_id is not None or payload.control_reference is not None:
            raise HTTPException(status_code=422, detail="Policy mappings require only policy_document_id")
        policy = await (
            await session.connection.execute(
                "select id, public_id, title from policy_documents where public_id = %s and status <> 'retired'",
                (payload.policy_document_id,),
            )
        ).fetchone()
        if policy is None:
            raise HTTPException(status_code=404, detail="Policy document not found")
        policy_internal_id = policy["id"]
        target_key = str(policy["public_id"])
        target_title = policy["title"]
    else:
        if payload.policy_document_id is not None or payload.framework_pack_version_id is None or not payload.control_reference:
            raise HTTPException(status_code=422, detail="Control mappings require a framework version and control reference")
        catalog = {
            (item["framework_pack_version_id"], item["reference"]): item
            for item in await _control_catalog(session)
        }
        control = catalog.get((payload.framework_pack_version_id, payload.control_reference))
        if control is None:
            raise HTTPException(status_code=422, detail="Control is not part of a tenant assessment")
        target_key = f"{payload.framework_pack_version_id}:{payload.control_reference}"
        target_title = control["title"]
        framework = control["framework"]

    try:
        assignment = await (
            await session.connection.execute(
                """
                insert into responsibility_assignments (
                  organization_id, responsibility_role_id, target_type,
                  policy_document_id, framework_pack_version_id, control_reference,
                  raci, delivery_model, notes, assigned_by
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning public_id as id, raci, delivery_model, notes, assigned_at
                """,
                (
                    session.identity.organization_id,
                    role["id"],
                    payload.target_type,
                    policy_internal_id,
                    payload.framework_pack_version_id,
                    payload.control_reference,
                    payload.raci,
                    payload.delivery_model,
                    payload.notes,
                    session.identity.actor_id,
                ),
            )
        ).fetchone()
    except UniqueViolation as conflict:
        raise HTTPException(
            status_code=409,
            detail="This responsibility is duplicated or the target already has an accountable role",
        ) from conflict
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'responsibility.assignment_created', 'responsibility_assignment', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(assignment["id"]),
            Jsonb({"role_id": str(payload.role_id), "target": target_key, "raci": payload.raci, "delivery_model": payload.delivery_model}),
        ),
    )
    return {
        **assignment,
        "role_id": role["public_id"],
        "role_name": role["name"],
        "role_party": role["party"],
        "target_type": payload.target_type,
        "target_key": target_key,
        "target_title": target_title,
        "framework": framework,
    }


@router.delete(
    "/v1/responsibility-assignments/{assignment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["responsibilities"],
    summary="Remove a responsibility mapping",
    operation_id="deleteResponsibilityAssignment",
)
async def delete_responsibility_assignment(
    assignment_id: UUID,
    session: TenantDatabaseSession,
) -> None:
    """Remove a tenant mapping while preserving an append-only audit event."""
    _require_admin(session)
    try:
        deleted = await session.connection.execute(
            "delete from responsibility_assignments where public_id = %s returning public_id",
            (assignment_id,),
        )
    except ForeignKeyViolation as conflict:
        raise HTTPException(status_code=409, detail="Responsibility assignment is still referenced") from conflict
    if await deleted.fetchone() is None:
        raise HTTPException(status_code=404, detail="Responsibility assignment not found")
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id
        ) values (%s, %s, 'responsibility.assignment_removed', 'responsibility_assignment', %s)
        """,
        (session.identity.organization_id, session.identity.actor_id, str(assignment_id)),
    )
