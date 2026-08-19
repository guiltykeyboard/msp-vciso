"""Add tenant public trust centers and verified custom domains.

Revision ID: 0013_tenant_trust_centers
Revises: 0012_responsibility_matrix
Create Date: 2026-08-19
"""

# Tenant RLS policy setup follows the established migration pattern.
# pylint: disable=invalid-name,no-member,duplicate-code

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0013_tenant_trust_centers"
down_revision: str | None = "0012_responsibility_matrix"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create tenant trust profiles, public resources, and domain bindings."""
    op.create_unique_constraint(
        "policy_document_versions_id_organization_unique",
        "policy_document_versions",
        ["id", "organization_id"],
    )
    op.create_table(
        "trust_center_profiles",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("headline", sa.Text(), nullable=False),
        sa.Column("overview", sa.Text(), nullable=False),
        sa.Column("security_contact_email", sa.Text(), nullable=True),
        sa.Column("primary_color", sa.Text(), server_default="#14532d", nullable=False),
        sa.Column("status", sa.Text(), server_default="draft", nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("status in ('draft', 'published')", name="trust_center_profiles_status_allowed"),
        sa.CheckConstraint("primary_color ~ '^#[0-9a-f]{6}$'", name="trust_center_profiles_color_hex"),
        sa.CheckConstraint("security_contact_email is null or security_contact_email = lower(security_contact_email)", name="trust_center_profiles_email_lowercase"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("organization_id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_table(
        "trust_center_resources",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=False),
        sa.Column("policy_document_version_id", sa.BigInteger(), nullable=False),
        sa.Column("public_title", sa.Text(), nullable=False),
        sa.Column("public_summary", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("published_by", sa.Uuid(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("category in ('policy', 'assurance', 'privacy', 'compliance')", name="trust_center_resources_category_allowed"),
        sa.ForeignKeyConstraint(
            ["policy_document_id", "organization_id"],
            ["policy_documents.id", "policy_documents.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_document_version_id", "organization_id"],
            ["policy_document_versions.id", "policy_document_versions.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["published_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("organization_id", "policy_document_id", name="trust_center_resources_document_unique"),
    )
    op.create_table(
        "trust_center_domains",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("verification_token", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("tls_provider", sa.Text(), server_default="platform_managed", nullable=False),
        sa.Column("certificate_status", sa.Text(), server_default="not_requested", nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("hostname = lower(hostname)", name="trust_center_domains_hostname_lowercase"),
        sa.CheckConstraint("status in ('pending', 'verified', 'active', 'disabled')", name="trust_center_domains_status_allowed"),
        sa.CheckConstraint("tls_provider in ('platform_managed', 'azure_managed', 'caddy_acme')", name="trust_center_domains_tls_provider_allowed"),
        sa.CheckConstraint("certificate_status in ('not_requested', 'provisioning', 'active', 'error')", name="trust_center_domains_certificate_status_allowed"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index("trust_center_domains_hostname_unique", "trust_center_domains", [sa.text("lower(hostname)")], unique=True)

    tenant_expression = "(select watchtower_private.current_organization_id())"
    for table_name in ("trust_center_profiles", "trust_center_resources", "trust_center_domains"):
        op.execute(f"alter table {table_name} enable row level security")
        op.execute(f"alter table {table_name} force row level security")
        op.execute(
            f"create policy {table_name}_tenant_select on {table_name} for select to watchtower_app "
            f"using (organization_id = {tenant_expression})"
        )
        op.execute(
            f"create policy {table_name}_tenant_insert on {table_name} for insert to watchtower_app "
            f"with check (organization_id = {tenant_expression})"
        )
        op.execute(
            f"create policy {table_name}_tenant_update on {table_name} for update to watchtower_app "
            f"using (organization_id = {tenant_expression}) with check (organization_id = {tenant_expression})"
        )
        op.execute(
            f"create policy {table_name}_tenant_delete on {table_name} for delete to watchtower_app "
            f"using (organization_id = {tenant_expression})"
        )
    op.execute("grant select, insert, update, delete on trust_center_profiles, trust_center_resources, trust_center_domains to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")

    op.execute(
        """
        create function watchtower_private.public_trust_center(request_hostname text, requested_slug text)
        returns jsonb
        language sql
        security definer
        stable
        set search_path = ''
        as $$
          select jsonb_build_object(
            'organization_slug', organizations.slug,
            'display_name', profiles.display_name,
            'headline', profiles.headline,
            'overview', profiles.overview,
            'security_contact_email', profiles.security_contact_email,
            'primary_color', profiles.primary_color,
            'updated_at', profiles.updated_at,
            'resources', coalesce((
              select jsonb_agg(jsonb_build_object(
                'id', resources.public_id,
                'policy_document_id', documents.public_id,
                'title', resources.public_title,
                'summary', resources.public_summary,
                'category', resources.category,
                'document_type', documents.document_type,
                'version', versions.version_number,
                'published_at', resources.published_at
              ) order by resources.category, resources.public_title)
              from public.trust_center_resources resources
              join public.policy_documents documents on documents.id = resources.policy_document_id
              join public.policy_document_versions versions on versions.id = resources.policy_document_version_id
              where resources.organization_id = profiles.organization_id
            ), '[]'::jsonb)
          )
          from public.trust_center_profiles profiles
          join public.organizations organizations on organizations.id = profiles.organization_id
          where profiles.status = 'published'
            and (
              (requested_slug is not null and organizations.slug = requested_slug)
              or
              (requested_slug is null and exists (
                select 1 from public.trust_center_domains domains
                where domains.organization_id = profiles.organization_id
                  and domains.hostname = request_hostname
                  and domains.status = 'active'
              ))
            )
          order by organizations.id
          limit 1
        $$
        """
    )
    op.execute("revoke all on function watchtower_private.public_trust_center(text, text) from public")
    op.execute("grant execute on function watchtower_private.public_trust_center(text, text) to watchtower_app")
    op.execute(
        """
        create function watchtower_private.trust_domain_tls_authorized(request_hostname text)
        returns boolean
        language sql
        security definer
        stable
        set search_path = ''
        as $$
          select exists (
            select 1
            from public.trust_center_domains domains
            join public.trust_center_profiles profiles on profiles.organization_id = domains.organization_id
            where domains.hostname = request_hostname
              and domains.status = 'active'
              and profiles.status = 'published'
          )
        $$
        """
    )
    op.execute("revoke all on function watchtower_private.trust_domain_tls_authorized(text) from public")
    op.execute("grant execute on function watchtower_private.trust_domain_tls_authorized(text) to watchtower_app")


def downgrade() -> None:
    """Remove public trust center capabilities."""
    op.execute("drop function watchtower_private.trust_domain_tls_authorized(text)")
    op.execute("drop function watchtower_private.public_trust_center(text, text)")
    op.drop_table("trust_center_domains")
    op.drop_table("trust_center_resources")
    op.drop_table("trust_center_profiles")
    op.drop_constraint("policy_document_versions_id_organization_unique", "policy_document_versions", type_="unique")
