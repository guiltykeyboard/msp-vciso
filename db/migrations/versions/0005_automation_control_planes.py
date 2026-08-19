"""Add Microsoft connector and endpoint collector control planes.

Revision ID: 0005_automation_control_planes
Revises: 0004_evidence_lifecycle
Create Date: 2026-08-18
"""

# pylint: disable=duplicate-code,invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0005_automation_control_planes"
down_revision: str | None = "0004_evidence_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create tenant-mapped connector, enrollment, device, and observation state."""
    op.create_table(
        "integration_connections",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("external_tenant_id", sa.Text(), nullable=False),
        sa.Column("cloud", sa.Text(), nullable=False),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("encrypted_client_secret", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.Text(), server_default="configured", nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("provider = 'microsoft_graph'", name="integration_connections_provider_allowed"),
        sa.CheckConstraint("cloud in ('commercial', 'gcc_high', 'dod')", name="integration_connections_cloud_allowed"),
        sa.CheckConstraint("status in ('configured', 'healthy', 'error', 'revoked')", name="integration_connections_status_allowed"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("organization_id", "provider", "external_tenant_id"),
    )
    op.create_table(
        "sites",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("organization_id", "name"),
        sa.UniqueConstraint("id", "organization_id"),
    )
    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("secret_hash", sa.LargeBinary(), nullable=False),
        sa.Column("allowed_platforms", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("max_uses", sa.Integer(), server_default="1", nullable=False),
        sa.Column("use_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("max_uses between 1 and 10000", name="agent_enrollment_tokens_max_uses_range"),
        sa.CheckConstraint("use_count between 0 and max_uses", name="agent_enrollment_tokens_use_count_range"),
        sa.ForeignKeyConstraint(["site_id", "organization_id"], ["sites.id", "sites.organization_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("secret_hash"),
    )
    op.create_table(
        "agents",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), nullable=False),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("credential_hash", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column("agent_version", sa.Text(), nullable=False),
        sa.Column("last_check_in_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("platform in ('windows', 'macos', 'linux')", name="agents_platform_allowed"),
        sa.CheckConstraint("status in ('active', 'stale', 'revocation_pending', 'revoked', 'uninstall_acknowledged')", name="agents_status_allowed"),
        sa.ForeignKeyConstraint(["site_id", "organization_id"], ["sites.id", "sites.organization_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("credential_hash"),
        sa.UniqueConstraint("id", "organization_id"),
    )
    op.create_table(
        "agent_observations",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.Uuid(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("facts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["agent_id", "organization_id"], ["agents.id", "agents.organization_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "idempotency_key"),
    )

    tenant_expression = "(select watchtower_private.current_organization_id())"
    tables = ("integration_connections", "sites", "agent_enrollment_tokens", "agents", "agent_observations")
    for table_name in tables:
        op.execute(f"alter table {table_name} enable row level security")
        op.execute(f"alter table {table_name} force row level security")
        for action in ("select", "insert", "update"):
            qualifier = "using" if action in {"select", "update"} else "with check"
            suffix = f" with check (organization_id = {tenant_expression})" if action == "update" else ""
            op.execute(
                f"create policy {table_name}_tenant_{action} on {table_name} for {action} to watchtower_app "
                f"{qualifier} (organization_id = {tenant_expression}){suffix}"
            )
    op.execute("grant select, insert, update on integration_connections, sites, agent_enrollment_tokens, agents, agent_observations to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")
    op.execute(
        """
        create function watchtower_private.consume_agent_enrollment(
          token_id uuid, presented_hash bytea, requested_platform text
        ) returns table (organization_id uuid, site_id bigint)
        language sql security definer set search_path = '' as $$
          update public.agent_enrollment_tokens
          set use_count = use_count + 1
          where public_id = token_id
            and secret_hash = presented_hash
            and requested_platform = any(allowed_platforms)
            and revoked_at is null and expires_at > now() and use_count < max_uses
          returning organization_id, site_id
        $$
        """
    )
    op.execute(
        """
        create function watchtower_private.resolve_agent_credential(
          presented_hash bytea
        ) returns table (organization_id uuid, agent_id bigint, agent_public_id uuid, agent_status text)
        language sql security definer stable set search_path = '' as $$
          select organization_id, id, public_id, status
          from public.agents
          where credential_hash = presented_hash
        $$
        """
    )
    op.execute("revoke all on function watchtower_private.consume_agent_enrollment(uuid, bytea, text) from public")
    op.execute("revoke all on function watchtower_private.resolve_agent_credential(bytea) from public")
    op.execute("grant execute on function watchtower_private.consume_agent_enrollment(uuid, bytea, text) to watchtower_app")
    op.execute("grant execute on function watchtower_private.resolve_agent_credential(bytea) to watchtower_app")


def downgrade() -> None:
    """Remove connector and collector control-plane state."""
    op.execute("drop function watchtower_private.resolve_agent_credential(bytea)")
    op.execute("drop function watchtower_private.consume_agent_enrollment(uuid, bytea, text)")
    for table_name in ("agent_observations", "agents", "agent_enrollment_tokens", "sites", "integration_connections"):
        op.drop_table(table_name)
