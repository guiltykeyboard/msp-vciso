"""Tenant trust center publishing and verified custom-domain routes."""

import ipaddress
import re
import secrets
from typing import Any
from uuid import UUID

import dns.asyncresolver
import dns.exception
from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import (
    PublicTrustCenterResponse,
    TrustCenterManagementResponse,
    TrustCenterProfileUpdate,
    TrustDomainCreate,
    TrustDomainResponse,
    TrustResourceCreate,
    TrustResourceResponse,
)


router = APIRouter()
TRUST_ADMINS = frozenset({"customer_admin", "msp_admin"})
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _require_admin(session: TenantDatabaseSession) -> None:
    if session.identity.role not in TRUST_ADMINS:
        raise HTTPException(status_code=403, detail="This tenant role cannot manage its trust center")


def normalize_hostname(value: str | None) -> str:
    """Return a canonical ASCII DNS hostname while rejecting unsafe targets."""
    if not value:
        raise HTTPException(status_code=422, detail="A DNS hostname is required")
    candidate = value.strip().rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as problem:
        raise HTTPException(status_code=422, detail="Custom hostname is not valid IDNA") from problem
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=422, detail="Custom hostname must not be an IP address")
    labels = candidate.split(".")
    if len(labels) < 3 or len(candidate) > 253 or any(not HOST_LABEL.fullmatch(label) for label in labels):
        raise HTTPException(status_code=422, detail="Use a valid subdomain such as trust.customer.example")
    return candidate


async def lookup_txt(name: str) -> set[str]:
    """Resolve DNS TXT values for ownership verification."""
    answers = await dns.asyncresolver.resolve(name, "TXT", lifetime=5)
    return {b"".join(answer.strings).decode("utf-8") for answer in answers}


async def lookup_cname(name: str) -> str:
    """Resolve the direct CNAME target required for TLS provisioning."""
    answers = await dns.asyncresolver.resolve(name, "CNAME", lifetime=5)
    return str(answers[0].target).rstrip(".").lower()


def _domain_response(row: dict[str, Any], cname_target: str | None) -> dict[str, Any]:
    hostname = row["hostname"]
    verification_token = row.pop("verification_token")
    return {
        **row,
        "verification_record_name": f"_watchtower-trust.{hostname}",
        "verification_record_value": f"watchtower-domain-verification={verification_token}",
        "cname_target": cname_target,
    }


async def _management(session: TenantDatabaseSession, cname_target: str | None) -> dict[str, Any]:
    profile = await (
        await session.connection.execute(
            """
            select display_name, headline, overview, security_contact_email,
                   primary_color, status
            from trust_center_profiles
            """
        )
    ).fetchone()
    organization = await (
        await session.connection.execute("select slug from organizations")
    ).fetchone()
    resources = await (
        await session.connection.execute(
            """
            select resources.public_id as id, documents.public_id as policy_document_id,
                   resources.public_title as title, resources.public_summary as summary,
                   resources.category, documents.document_type,
                   versions.version_number as version, resources.published_at
            from trust_center_resources resources
            join policy_documents documents on documents.id = resources.policy_document_id
            join policy_document_versions versions on versions.id = resources.policy_document_version_id
            order by resources.category, resources.public_title
            """
        )
    ).fetchall()
    domains = await (
        await session.connection.execute(
            """
            select public_id as id, hostname, verification_token, status,
                   tls_provider, certificate_status, verified_at, activated_at,
                   last_error, created_at
            from trust_center_domains
            order by hostname
            """
        )
    ).fetchall()
    policies = await (
        await session.connection.execute(
            """
            select documents.public_id as id, documents.title, documents.document_type,
                   documents.status, documents.owner_display_name, documents.review_due_at,
                   documents.current_version,
                   (select count(*) from policy_control_links links where links.policy_document_id = documents.id) as control_count,
                   (select count(*) from policy_evidence_links links where links.policy_document_id = documents.id) as evidence_count,
                   documents.updated_at
            from policy_documents documents
            where documents.status = 'approved'
              and not exists (
                select 1 from trust_center_resources resources
                where resources.policy_document_id = documents.id
              )
            order by documents.title
            """
        )
    ).fetchall()
    return {
        "profile": profile,
        "organization_slug": organization["slug"],
        "resources": resources,
        "domains": [_domain_response(dict(row), cname_target) for row in domains],
        "approved_policies": policies,
    }


@router.get(
    "/v1/trust-center",
    response_model=TrustCenterManagementResponse,
    tags=["trust centers"],
    summary="Get tenant trust center configuration",
    operation_id="getTrustCenter",
)
async def get_trust_center(session: TenantDatabaseSession, request: Request) -> dict[str, Any]:
    """Return tenant-managed public content, resources, and domain states."""
    return await _management(session, request.app.state.settings.trust_center.cname_target)


@router.put(
    "/v1/trust-center",
    response_model=TrustCenterManagementResponse,
    tags=["trust centers"],
    summary="Save and publish a tenant trust center",
    operation_id="updateTrustCenter",
)
async def update_trust_center(
    payload: TrustCenterProfileUpdate,
    session: TenantDatabaseSession,
    request: Request,
) -> dict[str, Any]:
    """Upsert the allow-listed profile fields and explicit publication state."""
    _require_admin(session)
    email = payload.security_contact_email.lower() if payload.security_contact_email else None
    await session.connection.execute(
        """
        insert into trust_center_profiles (
          organization_id, display_name, headline, overview,
          security_contact_email, primary_color, status, updated_by
        ) values (%s, %s, %s, %s, %s, %s, %s, %s)
        on conflict (organization_id) do update set
          display_name = excluded.display_name,
          headline = excluded.headline,
          overview = excluded.overview,
          security_contact_email = excluded.security_contact_email,
          primary_color = excluded.primary_color,
          status = excluded.status,
          updated_by = excluded.updated_by,
          updated_at = now()
        """,
        (
            session.identity.organization_id,
            payload.display_name.strip(),
            payload.headline.strip(),
            payload.overview.strip(),
            email,
            payload.primary_color.lower(),
            payload.status,
            session.identity.actor_id,
        ),
    )
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'trust_center.profile_updated', 'trust_center', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(session.identity.organization_id),
            Jsonb({"status": payload.status}),
        ),
    )
    return await _management(session, request.app.state.settings.trust_center.cname_target)


@router.post(
    "/v1/trust-center/resources",
    response_model=TrustResourceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["trust centers"],
    summary="Publish approved policy metadata",
    operation_id="createTrustResource",
)
async def create_trust_resource(
    payload: TrustResourceCreate,
    session: TenantDatabaseSession,
) -> dict[str, Any]:
    """Pin public-safe metadata to the currently approved policy version."""
    _require_admin(session)
    document = await (
        await session.connection.execute(
            """
            select documents.id, documents.public_id, documents.document_type,
                   versions.id as version_id, versions.version_number
            from policy_documents documents
            join policy_document_versions versions
              on versions.policy_document_id = documents.id
             and versions.version_number = documents.current_version
            where documents.public_id = %s and documents.status = 'approved'
            """,
            (payload.policy_document_id,),
        )
    ).fetchone()
    if document is None:
        raise HTTPException(status_code=422, detail="Only an approved tenant policy version can be published")
    try:
        resource = await (
            await session.connection.execute(
                """
                insert into trust_center_resources (
                  organization_id, policy_document_id, policy_document_version_id,
                  public_title, public_summary, category, published_by
                ) values (%s, %s, %s, %s, %s, %s, %s)
                returning public_id as id, public_title as title,
                          public_summary as summary, category, published_at
                """,
                (
                    session.identity.organization_id,
                    document["id"],
                    document["version_id"],
                    payload.public_title.strip(),
                    payload.public_summary.strip(),
                    payload.category,
                    session.identity.actor_id,
                ),
            )
        ).fetchone()
    except UniqueViolation as conflict:
        raise HTTPException(status_code=409, detail="This policy is already published") from conflict
    await session.connection.execute(
        """
        insert into audit_events (
          organization_id, actor_id, event_type, target_type, target_id, details
        ) values (%s, %s, 'trust_center.resource_published', 'trust_resource', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(resource["id"]),
            Jsonb({"policy_document_id": str(payload.policy_document_id), "version": document["version_number"]}),
        ),
    )
    return {
        **resource,
        "policy_document_id": document["public_id"],
        "document_type": document["document_type"],
        "version": document["version_number"],
    }


@router.delete(
    "/v1/trust-center/resources/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["trust centers"],
    summary="Unpublish a trust center resource",
    operation_id="deleteTrustResource",
)
async def delete_trust_resource(resource_id: UUID, session: TenantDatabaseSession) -> None:
    """Remove public metadata without changing the underlying controlled policy."""
    _require_admin(session)
    deleted = await session.connection.execute(
        "delete from trust_center_resources where public_id = %s returning public_id",
        (resource_id,),
    )
    if await deleted.fetchone() is None:
        raise HTTPException(status_code=404, detail="Trust center resource not found")
    await session.connection.execute(
        """
        insert into audit_events (organization_id, actor_id, event_type, target_type, target_id)
        values (%s, %s, 'trust_center.resource_unpublished', 'trust_resource', %s)
        """,
        (session.identity.organization_id, session.identity.actor_id, str(resource_id)),
    )


@router.post(
    "/v1/trust-center/domains",
    response_model=TrustDomainResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["trust centers"],
    summary="Register a custom trust center domain",
    operation_id="createTrustDomain",
)
async def create_trust_domain(
    payload: TrustDomainCreate,
    session: TenantDatabaseSession,
    request: Request,
) -> dict[str, Any]:
    """Register a hostname and return its DNS ownership challenge."""
    _require_admin(session)
    hostname = normalize_hostname(payload.hostname)
    existing_count = await (
        await session.connection.execute(
            "select count(*) as count from trust_center_domains where status <> 'disabled'"
        )
    ).fetchone()
    if existing_count["count"] >= 5:
        raise HTTPException(status_code=409, detail="A tenant can have at most five enabled trust domains")
    try:
        domain = await (
            await session.connection.execute(
                """
                insert into trust_center_domains (
                  organization_id, hostname, verification_token, tls_provider, created_by
                ) values (%s, %s, %s, %s, %s)
                returning public_id as id, hostname, verification_token, status,
                          tls_provider, certificate_status, verified_at, activated_at,
                          last_error, created_at
                """,
                (
                    session.identity.organization_id,
                    hostname,
                    secrets.token_urlsafe(24),
                    payload.tls_provider,
                    session.identity.actor_id,
                ),
            )
        ).fetchone()
    except UniqueViolation as conflict:
        raise HTTPException(status_code=409, detail="This hostname is already registered") from conflict
    await session.connection.execute(
        """
        insert into audit_events (organization_id, actor_id, event_type, target_type, target_id, details)
        values (%s, %s, 'trust_center.domain_registered', 'trust_domain', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(domain["id"]),
            Jsonb({"hostname": hostname, "tls_provider": payload.tls_provider}),
        ),
    )
    return _domain_response(dict(domain), request.app.state.settings.trust_center.cname_target)


@router.post(
    "/v1/trust-center/domains/{domain_id}:verify",
    response_model=TrustDomainResponse,
    tags=["trust centers"],
    summary="Verify custom-domain DNS ownership",
    operation_id="verifyTrustDomain",
)
async def verify_trust_domain(
    domain_id: UUID,
    session: TenantDatabaseSession,
    request: Request,
) -> dict[str, Any]:
    """Confirm the tenant's unique TXT challenge before allowing activation."""
    _require_admin(session)
    domain = await (
        await session.connection.execute(
            "select * from trust_center_domains where public_id = %s and status in ('pending', 'verified') for update",
            (domain_id,),
        )
    ).fetchone()
    if domain is None:
        raise HTTPException(status_code=404, detail="Pending trust domain not found")
    expected = f"watchtower-domain-verification={domain['verification_token']}"
    try:
        records = await lookup_txt(f"_watchtower-trust.{domain['hostname']}")
    except (dns.exception.DNSException, UnicodeError) as problem:
        raise HTTPException(status_code=422, detail="The ownership TXT record could not be resolved") from problem
    if expected not in records:
        raise HTTPException(status_code=422, detail="The ownership TXT record does not match")
    updated = await (
        await session.connection.execute(
            """
            update trust_center_domains
            set status = 'verified', verified_at = coalesce(verified_at, now()), last_error = null
            where id = %s
            returning public_id as id, hostname, verification_token, status,
                      tls_provider, certificate_status, verified_at, activated_at,
                      last_error, created_at
            """,
            (domain["id"],),
        )
    ).fetchone()
    await session.connection.execute(
        """
        insert into audit_events (organization_id, actor_id, event_type, target_type, target_id)
        values (%s, %s, 'trust_center.domain_verified', 'trust_domain', %s)
        """,
        (session.identity.organization_id, session.identity.actor_id, str(domain_id)),
    )
    return _domain_response(dict(updated), request.app.state.settings.trust_center.cname_target)


@router.post(
    "/v1/trust-center/domains/{domain_id}:activate",
    response_model=TrustDomainResponse,
    tags=["trust centers"],
    summary="Authorize custom-domain TLS provisioning",
    operation_id="activateTrustDomain",
)
async def activate_trust_domain(
    domain_id: UUID,
    session: TenantDatabaseSession,
    request: Request,
) -> dict[str, Any]:
    """Require the verified hostname to point directly at the configured edge."""
    _require_admin(session)
    target = request.app.state.settings.trust_center.cname_target
    if not target:
        raise HTTPException(status_code=503, detail="Custom-domain routing is not configured")
    domain = await (
        await session.connection.execute(
            "select * from trust_center_domains where public_id = %s and status = 'verified' for update",
            (domain_id,),
        )
    ).fetchone()
    if domain is None:
        raise HTTPException(status_code=409, detail="Verify the trust domain before activation")
    try:
        cname = await lookup_cname(domain["hostname"])
    except dns.exception.DNSException as problem:
        raise HTTPException(status_code=422, detail="The required CNAME record could not be resolved") from problem
    if cname != target.lower().rstrip("."):
        raise HTTPException(status_code=422, detail=f"CNAME must point directly to {target}")
    updated = await (
        await session.connection.execute(
            """
            update trust_center_domains
            set status = 'active', certificate_status = 'provisioning',
                activated_at = now(), last_error = null
            where id = %s
            returning public_id as id, hostname, verification_token, status,
                      tls_provider, certificate_status, verified_at, activated_at,
                      last_error, created_at
            """,
            (domain["id"],),
        )
    ).fetchone()
    await session.connection.execute(
        """
        insert into audit_events (organization_id, actor_id, event_type, target_type, target_id, details)
        values (%s, %s, 'trust_center.domain_activated', 'trust_domain', %s, %s)
        """,
        (
            session.identity.organization_id,
            session.identity.actor_id,
            str(domain_id),
            Jsonb({"hostname": domain["hostname"], "cname_target": target}),
        ),
    )
    return _domain_response(dict(updated), target)


@router.post(
    "/v1/trust-center/domains/{domain_id}:disable",
    response_model=TrustDomainResponse,
    tags=["trust centers"],
    summary="Disable a custom trust center domain",
    operation_id="disableTrustDomain",
)
async def disable_trust_domain(
    domain_id: UUID,
    session: TenantDatabaseSession,
    request: Request,
) -> dict[str, Any]:
    """Immediately remove a hostname from public routing and TLS authorization."""
    _require_admin(session)
    updated = await (
        await session.connection.execute(
            """
            update trust_center_domains
            set status = 'disabled', certificate_status = 'not_requested', last_error = null
            where public_id = %s and status <> 'disabled'
            returning public_id as id, hostname, verification_token, status,
                      tls_provider, certificate_status, verified_at, activated_at,
                      last_error, created_at
            """,
            (domain_id,),
        )
    ).fetchone()
    if updated is None:
        raise HTTPException(status_code=404, detail="Enabled trust domain not found")
    await session.connection.execute(
        """
        insert into audit_events (organization_id, actor_id, event_type, target_type, target_id)
        values (%s, %s, 'trust_center.domain_disabled', 'trust_domain', %s)
        """,
        (session.identity.organization_id, session.identity.actor_id, str(domain_id)),
    )
    return _domain_response(dict(updated), request.app.state.settings.trust_center.cname_target)


@router.get(
    "/v1/public/trust",
    response_model=PublicTrustCenterResponse,
    tags=["public trust centers"],
    summary="Get a published trust center by hostname or tenant slug",
    operation_id="getPublicTrustCenter",
)
async def get_public_trust_center(
    request: Request,
    response: Response,
    slug: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
    ),
) -> Any:
    """Resolve only explicitly published, public-safe data without tenant headers."""
    hostname = normalize_hostname(request.url.hostname) if slug is None else None
    pool = request.app.state.pool
    async with pool.connection() as connection:
        async with connection.transaction():
            row = await (
                await connection.execute(
                    "select watchtower_private.public_trust_center(%s, %s) as document",
                    (hostname, slug),
                )
            ).fetchone()
    if row is None or row["document"] is None:
        raise HTTPException(status_code=404, detail="Published trust center not found")
    response.headers["Cache-Control"] = "public, max-age=300"
    response.headers["Vary"] = "Host"
    return row["document"]


@router.get("/v1/internal/trust-domains:authorize", include_in_schema=False)
async def authorize_trust_domain_tls(
    request: Request,
    domain: str = Query(min_length=1, max_length=253),
    token: str = Query(min_length=1, max_length=512),
) -> Response:
    """Provide a constant-time, database-only authorization decision to a TLS edge."""
    expected_token = request.app.state.settings.trust_center.tls_authorization_secret
    if not expected_token or not secrets.compare_digest(token, expected_token):
        return Response(status_code=404)
    hostname = normalize_hostname(domain)
    pool = request.app.state.pool
    async with pool.connection() as connection:
        async with connection.transaction():
            row = await (
                await connection.execute(
                    "select watchtower_private.trust_domain_tls_authorized(%s) as allowed",
                    (hostname,),
                )
            ).fetchone()
    return Response(status_code=200 if row and row["allowed"] else 404)
