"""Create tenant policy and procedure records with immutable revisions.

Revision ID: 0009_policy_procedure_library
Revises: 0008_multi_tenant_auditors
Create Date: 2026-08-19
"""

# pylint: disable=duplicate-code,invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0009_policy_procedure_library"
down_revision: str | None = "0008_multi_tenant_auditors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create versioned tenant documents and their compliance relationships."""
    op.create_table(
        "policy_documents",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column(
            "public_id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("document_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="draft", nullable=False),
        sa.Column("owner_display_name", sa.Text(), nullable=True),
        sa.Column("review_due_at", sa.Date(), nullable=True),
        sa.Column("current_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "document_type in ('policy', 'procedure', 'standard', 'guideline')",
            name="policy_documents_type_allowed",
        ),
        sa.CheckConstraint(
            "status in ('draft', 'approved', 'retired')",
            name="policy_documents_status_allowed",
        ),
        sa.CheckConstraint(
            "current_version >= 1",
            name="policy_documents_current_version_positive",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["app_users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint(
            "id", "organization_id", name="policy_documents_id_organization_unique"
        ),
    )
    op.create_index(
        "policy_documents_organization_updated_idx",
        "policy_documents",
        ["organization_id", "updated_at"],
    )

    op.create_table(
        "policy_document_versions",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column(
            "public_id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("authored_by", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "version_number >= 1",
            name="policy_document_versions_number_positive",
        ),
        sa.ForeignKeyConstraint(
            ["policy_document_id", "organization_id"],
            ["policy_documents.id", "policy_documents.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authored_by"], ["app_users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint(
            "policy_document_id",
            "version_number",
            name="policy_document_versions_document_number_unique",
        ),
    )

    op.create_table(
        "policy_control_links",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=False),
        sa.Column("framework_pack_version_id", sa.BigInteger(), nullable=False),
        sa.Column("control_reference", sa.Text(), nullable=False),
        sa.Column("control_title", sa.Text(), nullable=False),
        sa.Column("linked_by", sa.Uuid(), nullable=False),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["policy_document_id", "organization_id"],
            ["policy_documents.id", "policy_documents.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["framework_pack_version_id"],
            ["framework_pack_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["linked_by"], ["app_users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "policy_document_id",
            "framework_pack_version_id",
            "control_reference",
            name="policy_control_links_document_control_unique",
        ),
    )

    op.create_table(
        "policy_evidence_links",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=False),
        sa.Column("evidence_observation_id", sa.BigInteger(), nullable=False),
        sa.Column("relationship", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("linked_by", sa.Uuid(), nullable=False),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "relationship in ('supports', 'implements', 'demonstrates')",
            name="policy_evidence_links_relationship_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["policy_document_id", "organization_id"],
            ["policy_documents.id", "policy_documents.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_observation_id", "organization_id"],
            ["evidence_observations.id", "evidence_observations.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["linked_by"], ["app_users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "policy_document_id",
            "evidence_observation_id",
            name="policy_evidence_links_document_evidence_unique",
        ),
    )

    tenant_expression = "(select watchtower_private.current_organization_id())"
    tables = (
        "policy_documents",
        "policy_document_versions",
        "policy_control_links",
        "policy_evidence_links",
    )
    for table_name in tables:
        op.execute(f"alter table {table_name} enable row level security")
        op.execute(f"alter table {table_name} force row level security")
        op.execute(
            f"create policy {table_name}_tenant_select on {table_name} "
            f"for select to watchtower_app using (organization_id = {tenant_expression})"
        )
        op.execute(
            f"create policy {table_name}_tenant_insert on {table_name} "
            f"for insert to watchtower_app with check "
            f"(organization_id = {tenant_expression})"
        )

    op.execute(
        "create policy policy_documents_tenant_update on policy_documents "
        f"for update to watchtower_app using (organization_id = {tenant_expression}) "
        f"with check (organization_id = {tenant_expression})"
    )
    for table_name in (
        "policy_document_versions",
        "policy_control_links",
        "policy_evidence_links",
    ):
        op.execute(
            f"create trigger {table_name}_immutable before update or delete on "
            f"{table_name} for each row execute function "
            "watchtower_private.reject_immutable_change()"
        )

    op.execute("grant select, insert, update on policy_documents to watchtower_app")
    op.execute(
        "grant select, insert on policy_document_versions, policy_control_links, "
        "policy_evidence_links to watchtower_app"
    )
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")


def downgrade() -> None:
    """Remove the tenant policy and procedure library."""
    op.drop_table("policy_evidence_links")
    op.drop_table("policy_control_links")
    op.drop_table("policy_document_versions")
    op.drop_table("policy_documents")
