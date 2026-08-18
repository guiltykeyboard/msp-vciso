"""Create the tenant and assessment foundation.

Revision ID: 0001_tenant_foundation
Revises:
Create Date: 2026-08-18
"""

# Alembic revision identifiers intentionally use framework-defined names, and
# the operation proxy exposes members dynamically.
# pylint: disable=invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001_tenant_foundation"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create tenant-owned tables, least-privilege grants, and forced RLS."""
    op.execute("revoke create on schema public from public")
    op.execute("create schema watchtower_private")
    op.execute("revoke all on schema watchtower_private from public")

    op.create_table(
        "service_providers",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'", name="service_providers_slug_format"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("service_provider_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'", name="organizations_slug_format"),
        sa.ForeignKeyConstraint(["service_provider_id"], ["service_providers.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("service_provider_id", "slug"),
    )
    op.create_index("organizations_service_provider_id_idx", "organizations", ["service_provider_id"])

    op.create_table(
        "app_users",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("external_subject", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("external_subject"),
    )
    op.create_table(
        "organization_memberships",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "role in ('customer_admin', 'control_owner', 'reviewer', 'auditor', 'msp_admin', 'msp_analyst')",
            name="organization_memberships_role_allowed",
        ),
        sa.CheckConstraint("status in ('active', 'suspended', 'expired')", name="organization_memberships_status_allowed"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("organization_id", "user_id"),
    )
    op.create_index("organization_memberships_user_id_idx", "organization_memberships", ["user_id"])
    op.create_index(
        "organization_memberships_active_user_idx",
        "organization_memberships",
        ["user_id", "organization_id"],
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "framework_pack_versions",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("pack_key", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="framework_pack_versions_sha256_format"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("pack_key", "version"),
        sa.UniqueConstraint("sha256"),
    )
    op.create_table(
        "assessments",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("framework_pack_version_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="draft", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("status in ('draft', 'active', 'in_review', 'complete', 'archived')", name="assessments_status_allowed"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["framework_pack_version_id"], ["framework_pack_versions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index("assessments_created_by_idx", "assessments", ["created_by"])
    op.create_index("assessments_framework_pack_version_id_idx", "assessments", ["framework_pack_version_id"])
    op.create_index("assessments_organization_created_idx", "assessments", ["organization_id", "created_at"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("audit_events_actor_id_idx", "audit_events", ["actor_id"])
    op.create_index("audit_events_organization_occurred_idx", "audit_events", ["organization_id", "occurred_at"])

    op.execute(
        """
        create function watchtower_private.current_organization_id()
        returns uuid
        language sql
        stable
        set search_path = ''
        as $$
          select nullif(current_setting('watchtower.organization_id', true), '')::uuid
        $$
        """
    )
    op.execute(
        """
        create function watchtower_private.reject_audit_event_change()
        returns trigger
        language plpgsql
        set search_path = ''
        as $$
        begin
          raise exception 'audit events are append-only' using errcode = '55000';
        end
        $$
        """
    )
    op.execute(
        """
        create trigger audit_events_immutable
        before update or delete on audit_events
        for each row execute function watchtower_private.reject_audit_event_change()
        """
    )

    for table_name in ("organizations", "organization_memberships", "assessments", "audit_events"):
        op.execute(f"alter table {table_name} enable row level security")
        op.execute(f"alter table {table_name} force row level security")

    tenant_expression = "(select watchtower_private.current_organization_id())"
    op.execute(
        f"create policy organizations_tenant_select on organizations for select to watchtower_app using (id = {tenant_expression})"
    )
    for table_name in ("organization_memberships", "assessments", "audit_events"):
        op.execute(
            f"create policy {table_name}_tenant_select on {table_name} for select to watchtower_app "
            f"using (organization_id = {tenant_expression})"
        )
    op.execute(
        f"create policy assessments_tenant_insert on assessments for insert to watchtower_app "
        f"with check (organization_id = {tenant_expression})"
    )
    op.execute(
        f"create policy assessments_tenant_update on assessments for update to watchtower_app "
        f"using (organization_id = {tenant_expression}) with check (organization_id = {tenant_expression})"
    )
    op.execute(
        f"create policy audit_events_tenant_insert on audit_events for insert to watchtower_app "
        f"with check (organization_id = {tenant_expression})"
    )

    op.execute("grant usage on schema public, watchtower_private to watchtower_app")
    op.execute("grant execute on function watchtower_private.current_organization_id() to watchtower_app")
    op.execute("grant select on organizations, organization_memberships, framework_pack_versions to watchtower_app")
    op.execute("grant select, insert, update on assessments to watchtower_app")
    op.execute("grant select, insert on audit_events to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")


def downgrade() -> None:
    """Remove the initial schema without modifying externally provisioned roles."""
    op.drop_table("audit_events")
    op.drop_table("assessments")
    op.drop_table("framework_pack_versions")
    op.drop_table("organization_memberships")
    op.drop_table("app_users")
    op.drop_table("organizations")
    op.drop_table("service_providers")
    op.execute("drop schema watchtower_private cascade")
