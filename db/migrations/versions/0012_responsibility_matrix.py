"""Add tenant organizational roles and responsibility mappings.

Revision ID: 0012_responsibility_matrix
Revises: 0011_policy_agreement_schedules
Create Date: 2026-08-19
"""

# Tenant RLS policy setup intentionally follows the established migration pattern.
# pylint: disable=invalid-name,no-member,duplicate-code

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0012_responsibility_matrix"
down_revision: str | None = "0011_policy_agreement_schedules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create role catalog, named holders, and RACI control/document mappings."""
    op.create_table(
        "responsibility_roles",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("party", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("party in ('customer', 'msp', 'vendor')", name="responsibility_roles_party_allowed"),
        sa.CheckConstraint("status in ('active', 'inactive')", name="responsibility_roles_status_allowed"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("id", "organization_id", name="responsibility_roles_id_organization_unique"),
    )
    op.create_index(
        "responsibility_roles_organization_name_unique",
        "responsibility_roles",
        ["organization_id", sa.text("lower(name)")],
        unique=True,
    )

    op.create_table(
        "responsibility_role_holders",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("responsibility_role_id", sa.BigInteger(), nullable=False),
        sa.Column("app_user_id", sa.Uuid(), nullable=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("is_primary", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("starts_on", sa.Date(), nullable=True),
        sa.Column("ends_on", sa.Date(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("email is null or email = lower(email)", name="responsibility_role_holders_email_lowercase"),
        sa.CheckConstraint("ends_on is null or starts_on is null or ends_on >= starts_on", name="responsibility_role_holders_dates_ordered"),
        sa.ForeignKeyConstraint(
            ["responsibility_role_id", "organization_id"],
            ["responsibility_roles.id", "responsibility_roles.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["app_user_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        "responsibility_role_holders_primary_unique",
        "responsibility_role_holders",
        ["responsibility_role_id"],
        unique=True,
        postgresql_where=sa.text("is_primary and ends_on is null"),
    )

    op.create_table(
        "responsibility_assignments",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("responsibility_role_id", sa.BigInteger(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=True),
        sa.Column("framework_pack_version_id", sa.BigInteger(), nullable=True),
        sa.Column("control_reference", sa.Text(), nullable=True),
        sa.Column("raci", sa.Text(), nullable=False),
        sa.Column("delivery_model", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("assigned_by", sa.Uuid(), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("target_type in ('policy', 'control')", name="responsibility_assignments_target_allowed"),
        sa.CheckConstraint("raci in ('responsible', 'accountable', 'consulted', 'informed')", name="responsibility_assignments_raci_allowed"),
        sa.CheckConstraint("delivery_model in ('customer', 'msp', 'shared', 'vendor')", name="responsibility_assignments_delivery_allowed"),
        sa.CheckConstraint(
            "(target_type = 'policy' and policy_document_id is not null and framework_pack_version_id is null and control_reference is null) or "
            "(target_type = 'control' and policy_document_id is null and framework_pack_version_id is not null and control_reference is not null)",
            name="responsibility_assignments_target_shape",
        ),
        sa.ForeignKeyConstraint(
            ["responsibility_role_id", "organization_id"],
            ["responsibility_roles.id", "responsibility_roles.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_document_id", "organization_id"],
            ["policy_documents.id", "policy_documents.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["framework_pack_version_id"], ["framework_pack_versions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["assigned_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        "responsibility_assignments_role_policy_unique",
        "responsibility_assignments",
        ["responsibility_role_id", "policy_document_id", "raci"],
        unique=True,
        postgresql_where=sa.text("target_type = 'policy'"),
    )
    op.create_index(
        "responsibility_assignments_role_control_unique",
        "responsibility_assignments",
        ["responsibility_role_id", "framework_pack_version_id", "control_reference", "raci"],
        unique=True,
        postgresql_where=sa.text("target_type = 'control'"),
    )
    op.create_index(
        "responsibility_assignments_policy_accountable_unique",
        "responsibility_assignments",
        ["organization_id", "policy_document_id"],
        unique=True,
        postgresql_where=sa.text("target_type = 'policy' and raci = 'accountable'"),
    )
    op.create_index(
        "responsibility_assignments_control_accountable_unique",
        "responsibility_assignments",
        ["organization_id", "framework_pack_version_id", "control_reference"],
        unique=True,
        postgresql_where=sa.text("target_type = 'control' and raci = 'accountable'"),
    )

    tenant_expression = "(select watchtower_private.current_organization_id())"
    tables = ("responsibility_roles", "responsibility_role_holders", "responsibility_assignments")
    for table_name in tables:
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
            f"create policy {table_name}_tenant_delete on {table_name} for delete to watchtower_app "
            f"using (organization_id = {tenant_expression})"
        )
    op.execute("grant select, insert, delete on responsibility_roles, responsibility_role_holders, responsibility_assignments to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")


def downgrade() -> None:
    """Remove responsibility mappings, holders, and organizational roles."""
    op.drop_table("responsibility_assignments")
    op.drop_table("responsibility_role_holders")
    op.drop_table("responsibility_roles")
