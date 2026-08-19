"""Add evidence quarantine, retention, and legal-hold state.

Revision ID: 0004_evidence_lifecycle
Revises: 0003_object_storage_uploads
Create Date: 2026-08-18
"""

# pylint: disable=duplicate-code,invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0004_evidence_lifecycle"
down_revision: str | None = "0003_object_storage_uploads"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create mutable operational state without weakening immutable evidence."""
    op.create_table(
        "evidence_retention_policies",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("retention_days", sa.Integer(), server_default="2555", nullable=False),
        sa.Column("object_lock_mode", sa.Text(), server_default="none", nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("retention_days between 1 and 36500", name="evidence_retention_policies_days_range"),
        sa.CheckConstraint(
            "object_lock_mode in ('none', 'governance', 'compliance')",
            name="evidence_retention_policies_lock_mode_allowed",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("organization_id"),
    )
    op.create_table(
        "evidence_artifact_lifecycle",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_observation_id", sa.BigInteger(), nullable=False),
        sa.Column("scan_status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("scan_engine", sa.Text(), nullable=True),
        sa.Column("scan_detail", sa.Text(), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("object_lock_mode", sa.Text(), server_default="none", nullable=False),
        sa.Column("legal_hold", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("legal_hold_reason", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "scan_status in ('pending', 'clean', 'quarantined', 'error')",
            name="evidence_artifact_lifecycle_scan_status_allowed",
        ),
        sa.CheckConstraint(
            "object_lock_mode in ('none', 'governance', 'compliance')",
            name="evidence_artifact_lifecycle_lock_mode_allowed",
        ),
        sa.CheckConstraint(
            "(legal_hold and legal_hold_reason is not null) or (not legal_hold and legal_hold_reason is null)",
            name="evidence_artifact_lifecycle_legal_hold_consistent",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_observation_id", "organization_id"],
            ["evidence_observations.id", "evidence_observations.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("evidence_observation_id"),
    )
    op.create_index(
        "evidence_artifact_lifecycle_org_status_idx",
        "evidence_artifact_lifecycle",
        ["organization_id", "scan_status"],
    )
    op.create_index(
        "evidence_artifact_lifecycle_retention_idx",
        "evidence_artifact_lifecycle",
        ["retention_until"],
    )

    tenant_expression = "(select watchtower_private.current_organization_id())"
    for table_name in ("evidence_retention_policies", "evidence_artifact_lifecycle"):
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
        "grant select, insert, update on evidence_retention_policies, evidence_artifact_lifecycle to watchtower_app"
    )


def downgrade() -> None:
    """Remove evidence lifecycle configuration and state."""
    op.drop_table("evidence_artifact_lifecycle")
    op.drop_table("evidence_retention_policies")
