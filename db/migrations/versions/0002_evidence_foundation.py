"""Create immutable evidence observations and append-only reviews.

Revision ID: 0002_evidence_foundation
Revises: 0001_tenant_foundation
Create Date: 2026-08-18
"""

# Alembic revision identifiers intentionally use framework-defined names, and
# the operation proxy exposes members dynamically.
# pylint: disable=invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0002_evidence_foundation"
down_revision: str | None = "0001_tenant_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create tenant-owned evidence tables, policies, and immutable ledgers."""
    op.create_unique_constraint(
        "assessments_id_organization_unique",
        "assessments",
        ["id", "organization_id"],
    )
    op.create_table(
        "evidence_observations",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.BigInteger(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("collection_method", sa.Text(), nullable=False),
        sa.Column("source_type", sa.Text(), nullable=False),
        sa.Column("source_identifier", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("artifact_name", sa.Text(), nullable=False),
        sa.Column("media_type", sa.Text(), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.Column("sensitivity", sa.Text(), nullable=False),
        sa.Column(
            "normalized_facts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("submitted_by", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "collection_method in ('manual', 'api', 'endpoint', 'browser', 'import')",
            name="evidence_observations_collection_method_allowed",
        ),
        sa.CheckConstraint(
            "sensitivity in ('internal', 'confidential', 'security_record', 'cji')",
            name="evidence_observations_sensitivity_allowed",
        ),
        sa.CheckConstraint("byte_size >= 0", name="evidence_observations_byte_size_nonnegative"),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="evidence_observations_sha256_format"),
        sa.ForeignKeyConstraint(
            ["assessment_id", "organization_id"],
            ["assessments.id", "assessments.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["submitted_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("id", "organization_id", name="evidence_observations_id_organization_unique"),
    )
    op.create_index(
        "evidence_observations_organization_received_idx",
        "evidence_observations",
        ["organization_id", "received_at"],
    )
    op.create_index(
        "evidence_observations_assessment_received_idx",
        "evidence_observations",
        ["assessment_id", "received_at"],
    )
    op.create_index("evidence_observations_submitted_by_idx", "evidence_observations", ["submitted_by"])

    op.create_table(
        "evidence_reviews",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_observation_id", sa.BigInteger(), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("reviewed_by", sa.Uuid(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("decision in ('accepted', 'rejected')", name="evidence_reviews_decision_allowed"),
        sa.ForeignKeyConstraint(
            ["evidence_observation_id", "organization_id"],
            ["evidence_observations.id", "evidence_observations.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        "evidence_reviews_observation_reviewed_idx",
        "evidence_reviews",
        ["evidence_observation_id", "reviewed_at"],
    )
    op.create_index("evidence_reviews_organization_reviewed_idx", "evidence_reviews", ["organization_id", "reviewed_at"])
    op.create_index("evidence_reviews_reviewed_by_idx", "evidence_reviews", ["reviewed_by"])

    for table_name in ("evidence_observations", "evidence_reviews"):
        op.execute(f"alter table {table_name} enable row level security")
        op.execute(f"alter table {table_name} force row level security")

    tenant_expression = "(select watchtower_private.current_organization_id())"
    for table_name in ("evidence_observations", "evidence_reviews"):
        op.execute(
            f"create policy {table_name}_tenant_select on {table_name} for select to watchtower_app "
            f"using (organization_id = {tenant_expression})"
        )
        op.execute(
            f"create policy {table_name}_tenant_insert on {table_name} for insert to watchtower_app "
            f"with check (organization_id = {tenant_expression})"
        )

    op.execute(
        """
        create function watchtower_private.reject_immutable_change()
        returns trigger
        language plpgsql
        set search_path = ''
        as $$
        begin
          raise exception 'immutable records cannot be updated or deleted' using errcode = '55000';
        end
        $$
        """
    )
    op.execute(
        "create trigger evidence_observations_immutable before update or delete on evidence_observations "
        "for each row execute function watchtower_private.reject_immutable_change()"
    )
    op.execute(
        "create trigger evidence_reviews_immutable before update or delete on evidence_reviews "
        "for each row execute function watchtower_private.reject_immutable_change()"
    )

    op.execute("grant select, insert on evidence_observations, evidence_reviews to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")


def downgrade() -> None:
    """Remove evidence tables without changing the tenant foundation."""
    op.drop_table("evidence_reviews")
    op.drop_table("evidence_observations")
    op.execute("drop function watchtower_private.reject_immutable_change()")
    op.drop_constraint("assessments_id_organization_unique", "assessments", type_="unique")
