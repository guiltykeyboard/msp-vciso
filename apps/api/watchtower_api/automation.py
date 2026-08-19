"""Microsoft Graph and endpoint collector control-plane routes."""

from datetime import UTC, datetime
import hashlib
import json
import secrets
from typing import Annotated, Any
from urllib import error, parse, request
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Header, HTTPException, Request, status
from psycopg.types.json import Jsonb

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import (
    AgentEnrollmentResponse,
    AgentEnrollmentExchange,
    AgentEnrollmentTokenCreate,
    AgentEnrollmentTokenResponse,
    AgentObservationCreate,
    AgentObservationResponse,
    MicrosoftConnectionCreate,
    MicrosoftConnectionResponse,
    SiteCreate,
    SiteResponse,
)


router = APIRouter()
AUTOMATION_ADMINS = frozenset({"customer_admin", "msp_admin"})
GRAPH_ENDPOINTS = {
    "commercial": ("https://login.microsoftonline.com", "https://graph.microsoft.com"),
    "gcc_high": ("https://login.microsoftonline.us", "https://graph.microsoft.us"),
    "dod": ("https://login.microsoftonline.us", "https://dod-graph.microsoft.us"),
}


@router.get("/v1/dashboard", tags=["tenancy"])
async def get_dashboard(session: TenantDatabaseSession) -> Any:
    """Return tenant-scoped operational queues and health without synthetic metrics."""
    organization = await (
        await session.connection.execute("select id, name from organizations where id = %s", (session.identity.organization_id,))
    ).fetchone()
    assessments = await (
        await session.connection.execute(
            "select public_id as id, name, status, updated_at from assessments order by updated_at desc limit 8"
        )
    ).fetchall()
    evidence = await (
        await session.connection.execute(
            """
            select evidence.public_id as id, evidence.title, evidence.sensitivity,
                   lifecycle.scan_status, evidence.received_at
            from evidence_observations evidence
            left join evidence_artifact_lifecycle lifecycle on lifecycle.evidence_observation_id = evidence.id
            order by evidence.received_at desc limit 8
            """
        )
    ).fetchall()
    integrations = await (
        await session.connection.execute(
            "select public_id as id, display_name, provider, status, last_success_at from integration_connections order by created_at desc limit 8"
        )
    ).fetchall()
    endpoints = await (
        await session.connection.execute(
            "select public_id as id, hostname, platform, status, last_check_in_at from agents order by enrolled_at desc limit 8"
        )
    ).fetchall()
    audits = await (
        await session.connection.execute(
            "select event_type, target_type, target_id, occurred_at from audit_events order by occurred_at desc limit 8"
        )
    ).fetchall()
    return {
        "organization": organization,
        "identity": {
            "actor_id": session.identity.actor_id,
            "role": session.identity.role,
        },
        "assessments": assessments,
        "evidence": evidence,
        "integrations": integrations,
        "endpoints": endpoints,
        "audit": audits,
    }


def _secret_hash(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _cipher(application: Request) -> Fernet:
    key = application.app.state.settings.credential_encryption_key
    if not key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential encryption is not configured",
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as configuration_error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential encryption is misconfigured",
        ) from configuration_error


def _graph_get(url: str, token: str) -> Any:
    graph_request = request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with request.urlopen(graph_request, timeout=30) as response:  # nosec B310 - fixed HTTPS roots
        return json.load(response)


def _discover_graph(connection: dict[str, Any], client_secret: str) -> dict[str, Any]:
    authority, graph = GRAPH_ENDPOINTS[connection["cloud"]]
    token_body = parse.urlencode(
        {
            "client_id": connection["client_id"],
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": f"{graph}/.default",
        }
    ).encode()
    token_request = request.Request(
        f"{authority}/{connection['external_tenant_id']}/oauth2/v2.0/token",
        data=token_body,
        method="POST",
    )
    with request.urlopen(token_request, timeout=30) as response:  # nosec B310 - fixed HTTPS roots
        access_token = json.load(response)["access_token"]
    organization = _graph_get(f"{graph}/v1.0/organization?$select=id,displayName,verifiedDomains", access_token)
    domains = _graph_get(f"{graph}/v1.0/domains?$select=id,isDefault,isVerified", access_token)
    policies = _graph_get(
        f"{graph}/v1.0/identity/conditionalAccess/policies?$select=id,displayName,state",
        access_token,
    )
    return {
        "organization": organization.get("value", []),
        "domains": domains.get("value", []),
        "conditional_access_policies": policies.get("value", []),
        "collected_at": datetime.now(UTC).isoformat(),
        "cloud": connection["cloud"],
    }


@router.post("/v1/integrations/microsoft", response_model=MicrosoftConnectionResponse, status_code=201, tags=["integrations"])
async def create_microsoft_connection(
    payload: MicrosoftConnectionCreate,
    request_context: Request,
    session: TenantDatabaseSession,
) -> Any:
    """Store a tenant-mapped Graph connection with an encrypted secret."""
    if session.identity.role not in AUTOMATION_ADMINS:
        raise HTTPException(status_code=403, detail="This tenant role cannot manage integrations")
    encrypted_secret = _cipher(request_context).encrypt(payload.client_secret.encode())
    cursor = await session.connection.execute(
        """
        insert into integration_connections (
          organization_id, provider, display_name, external_tenant_id, cloud,
          client_id, encrypted_client_secret, created_by
        ) values (%s, 'microsoft_graph', %s, %s, %s, %s, %s, %s)
        returning public_id as id, display_name, external_tenant_id, cloud, client_id,
                  status, last_success_at, last_error, created_at
        """,
        (
            session.identity.organization_id,
            payload.display_name,
            str(payload.external_tenant_id),
            payload.cloud,
            str(payload.client_id),
            encrypted_secret,
            session.identity.actor_id,
        ),
    )
    return await cursor.fetchone()


@router.get("/v1/integrations/microsoft", response_model=list[MicrosoftConnectionResponse], tags=["integrations"])
async def list_microsoft_connections(session: TenantDatabaseSession) -> Any:
    """List redacted tenant-visible Microsoft connections."""
    cursor = await session.connection.execute(
        """
        select public_id as id, display_name, external_tenant_id, cloud, client_id,
               status, last_success_at, last_error, created_at
        from integration_connections where provider = 'microsoft_graph'
        order by created_at desc
        """
    )
    return await cursor.fetchall()


@router.post("/v1/integrations/microsoft/{connection_id}/discover", tags=["integrations"])
async def discover_microsoft_scope(
    connection_id: UUID,
    request_context: Request,
    session: TenantDatabaseSession,
) -> Any:
    """Collect read-only organization, domain, and conditional-access facts."""
    if session.identity.role not in AUTOMATION_ADMINS:
        raise HTTPException(status_code=403, detail="This tenant role cannot run integrations")
    cursor = await session.connection.execute(
        "select * from integration_connections where public_id = %s and status <> 'revoked' for update",
        (connection_id,),
    )
    connection = await cursor.fetchone()
    if connection is None:
        raise HTTPException(status_code=404, detail="Microsoft connection not found")
    try:
        secret = _cipher(request_context).decrypt(bytes(connection["encrypted_client_secret"])).decode()
        result = await __import__("asyncio").to_thread(_discover_graph, connection, secret)
    except (InvalidToken, UnicodeError, error.URLError, KeyError, ValueError) as graph_error:
        await session.connection.execute(
            "update integration_connections set status = 'error', last_error = %s where id = %s",
            (type(graph_error).__name__, connection["id"]),
        )
        raise HTTPException(status_code=502, detail="Microsoft Graph discovery failed") from graph_error
    await session.connection.execute(
        "update integration_connections set status = 'healthy', last_success_at = now(), last_error = null where id = %s",
        (connection["id"],),
    )
    await session.connection.execute(
        "insert into audit_events (organization_id, actor_id, event_type, target_type, target_id, details) values (%s, %s, 'integration.discovery_completed', 'integration_connection', %s, %s)",
        (session.identity.organization_id, session.identity.actor_id, str(connection_id), Jsonb({"provider": "microsoft_graph", "cloud": connection["cloud"]})),
    )
    return result


@router.post("/v1/sites", response_model=SiteResponse, status_code=201, tags=["endpoints"])
async def create_site(payload: SiteCreate, session: TenantDatabaseSession) -> Any:
    """Create a tenant site for endpoint enrollment."""
    if session.identity.role not in AUTOMATION_ADMINS:
        raise HTTPException(status_code=403, detail="This tenant role cannot create sites")
    cursor = await session.connection.execute(
        "insert into sites (organization_id, name, created_by) values (%s, %s, %s) returning public_id as id, name, created_at",
        (session.identity.organization_id, payload.name, session.identity.actor_id),
    )
    return await cursor.fetchone()


@router.post("/v1/agent-enrollment-tokens", response_model=AgentEnrollmentTokenResponse, status_code=201, tags=["endpoints"])
async def create_agent_enrollment_token(payload: AgentEnrollmentTokenCreate, session: TenantDatabaseSession) -> Any:
    """Issue a site-bound enrollment token and store only its hash."""
    if session.identity.role not in AUTOMATION_ADMINS:
        raise HTTPException(status_code=403, detail="This tenant role cannot issue enrollment tokens")
    if payload.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=422, detail="Enrollment expiry must be in the future")
    site_cursor = await session.connection.execute("select id from sites where public_id = %s", (payload.site_id,))
    site = await site_cursor.fetchone()
    if site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    token_id = uuid4()
    secret = secrets.token_urlsafe(32)
    await session.connection.execute(
        """
        insert into agent_enrollment_tokens (
          public_id, organization_id, site_id, secret_hash, allowed_platforms,
          max_uses, expires_at, created_by
        ) values (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (token_id, session.identity.organization_id, site["id"], _secret_hash(secret), payload.allowed_platforms, payload.max_uses, payload.expires_at, session.identity.actor_id),
    )
    return {"id": token_id, "token": f"{token_id}.{secret}", "expires_at": payload.expires_at}


@router.post("/v1/agent-enrollments:exchange", response_model=AgentEnrollmentResponse, tags=["endpoints"])
async def exchange_agent_enrollment(payload: AgentEnrollmentExchange, request_context: Request) -> Any:
    """Atomically consume an enrollment use and return a per-device credential once."""
    try:
        token_id_text, secret = payload.token.split(".", 1)
        token_id = UUID(token_id_text)
    except (ValueError, AttributeError) as parse_error:
        raise HTTPException(status_code=401, detail="Invalid enrollment token") from parse_error
    pool = request_context.app.state.pool
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute(
            "select * from watchtower_private.consume_agent_enrollment(%s, %s, %s)",
            (token_id, _secret_hash(secret), payload.platform),
        )
        enrollment = await cursor.fetchone()
        if enrollment is None:
            raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")
        await connection.execute("select set_config('watchtower.organization_id', %s, true)", (str(enrollment["organization_id"]),))
        device_secret = secrets.token_urlsafe(48)
        device_cursor = await connection.execute(
            """
            insert into agents (
              organization_id, site_id, platform, hostname, public_key,
              credential_hash, agent_version
            ) values (%s, %s, %s, %s, %s, %s, %s) returning public_id
            """,
            (enrollment["organization_id"], enrollment["site_id"], payload.platform, payload.hostname, payload.public_key, _secret_hash(device_secret), payload.agent_version),
        )
        device_id = (await device_cursor.fetchone())["public_id"]
        await connection.execute(
            "insert into audit_events (organization_id, event_type, target_type, target_id, details) values (%s, 'agent.enrolled', 'agent', %s, %s)",
            (enrollment["organization_id"], str(device_id), Jsonb({"platform": payload.platform, "token_id": str(token_id)})),
        )
    return {"device_id": device_id, "credential": device_secret}


@router.post("/v1/agents/{device_id}/check-ins", response_model=AgentObservationResponse, tags=["endpoints"])
async def agent_check_in(
    device_id: UUID,
    payload: AgentObservationCreate,
    request_context: Request,
    authorization: Annotated[str, Header()],
) -> Any:
    """Accept an idempotent posture observation authenticated by device credential."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing device credential")
    credential_hash = _secret_hash(authorization.removeprefix("Bearer "))
    pool = request_context.app.state.pool
    async with pool.connection() as connection, connection.transaction():
        cursor = await connection.execute(
            "select * from watchtower_private.resolve_agent_credential(%s)",
            (credential_hash,),
        )
        agent = await cursor.fetchone()
        if agent is None or agent["agent_public_id"] != device_id or agent["agent_status"] != "active":
            raise HTTPException(status_code=401, detail="Invalid device credential")
        await connection.execute("select set_config('watchtower.organization_id', %s, true)", (str(agent["organization_id"]),))
        await connection.execute(
            """
            insert into agent_observations (
              organization_id, agent_id, idempotency_key, schema_version, observed_at, facts
            ) values (%s, %s, %s, %s, %s, %s)
            on conflict (agent_id, idempotency_key) do nothing
            """,
            (agent["organization_id"], agent["agent_id"], payload.idempotency_key, payload.schema_version, payload.observed_at, Jsonb(payload.facts)),
        )
        await connection.execute(
            "update agents set last_check_in_at = now(), agent_version = coalesce(agent_version, agent_version) where id = %s",
            (agent["agent_id"],),
        )
        received_cursor = await connection.execute(
            "select received_at from agent_observations where agent_id = %s and idempotency_key = %s",
            (agent["agent_id"], payload.idempotency_key),
        )
        received_at = (await received_cursor.fetchone())["received_at"]
    return {"device_id": device_id, "idempotency_key": payload.idempotency_key, "received_at": received_at}
