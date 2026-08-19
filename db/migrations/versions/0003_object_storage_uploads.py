"""Create tenant-scoped direct-upload sessions.

Revision ID: 0003_object_storage_uploads
Revises: 0002_evidence_foundation
Create Date: 2026-08-18
"""

# Alembic revision identifiers intentionally use framework-defined names, and
# the operation proxy exposes members dynamically.
# pylint: disable=duplicate-code,invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0003_object_storage_uploads"
down_revision: str | None = "0002_evidence_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add object references and constrained, tenant-owned upload sessions."""
    op.add_column("evidence_observations", sa.Column("storage_provider", sa.Text(), nullable=True))
    op.add_column("evidence_observations", sa.Column("artifact_object_key", sa.Text(), nullable=True))
    op.create_check_constraint(
        "evidence_observations_storage_provider_allowed",
        "evidence_observations",
        "storage_provider is null or storage_provider in ('azure', 's3')",
    )
    op.create_check_constraint(
        "evidence_observations_storage_fields_together",
        "evidence_observations",
        "(storage_provider is null) = (artifact_object_key is null)",
    )
    op.create_check_constraint(
        "evidence_observations_byte_size_maximum",
        "evidence_observations",
        "byte_size <= 5368709120",
    )
    op.create_unique_constraint(
        "evidence_observations_artifact_object_key_unique",
        "evidence_observations",
        ["artifact_object_key"],
    )

    op.create_table(
        "evidence_upload_sessions",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.BigInteger(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("collection_method", sa.Text(), nullable=False),
        sa.Column("source_type", sa.Text(), nullable=False),
        sa.Column("source_identifier", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_evidence_id", sa.BigInteger(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("provider in ('azure', 's3')", name="evidence_upload_sessions_provider_allowed"),
        sa.CheckConstraint(
            "collection_method in ('manual', 'api', 'endpoint', 'browser', 'import')",
            name="evidence_upload_sessions_collection_method_allowed",
        ),
        sa.CheckConstraint(
            "sensitivity in ('internal', 'confidential', 'security_record', 'cji')",
            name="evidence_upload_sessions_sensitivity_allowed",
        ),
        sa.CheckConstraint("byte_size >= 0", name="evidence_upload_sessions_byte_size_nonnegative"),
        sa.CheckConstraint("byte_size <= 5368709120", name="evidence_upload_sessions_byte_size_maximum"),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="evidence_upload_sessions_sha256_format"),
        sa.CheckConstraint("status in ('pending', 'completed')", name="evidence_upload_sessions_status_allowed"),
        sa.CheckConstraint("expires_at > created_at", name="evidence_upload_sessions_expiry_after_creation"),
        sa.CheckConstraint(
            "(status = 'pending' and completed_evidence_id is null and completed_at is null) or "
            "(status = 'completed' and completed_evidence_id is not null and completed_at is not null)",
            name="evidence_upload_sessions_completion_consistent",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "organization_id"],
            ["assessments.id", "assessments.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["completed_evidence_id", "organization_id"],
            ["evidence_observations.id", "evidence_observations.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("object_key"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        "evidence_upload_sessions_organization_created_idx",
        "evidence_upload_sessions",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "evidence_upload_sessions_assessment_created_idx",
        "evidence_upload_sessions",
        ["assessment_id", "created_at"],
    )
    op.create_index("evidence_upload_sessions_created_by_idx", "evidence_upload_sessions", ["created_by"])
    op.create_index(
        "evidence_upload_sessions_pending_expiry_idx",
        "evidence_upload_sessions",
        ["expires_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )

    op.execute("alter table evidence_upload_sessions enable row level security")
    op.execute("alter table evidence_upload_sessions force row level security")
    tenant_expression = "(select watchtower_private.current_organization_id())"
    op.execute(
        "create policy evidence_upload_sessions_tenant_select on evidence_upload_sessions "
        f"for select to watchtower_app using (organization_id = {tenant_expression})"
    )
    op.execute(
        "create policy evidence_upload_sessions_tenant_insert on evidence_upload_sessions "
        f"for insert to watchtower_app with check (organization_id = {tenant_expression})"
    )
    op.execute(
        "create policy evidence_upload_sessions_tenant_update on evidence_upload_sessions "
        f"for update to watchtower_app using (organization_id = {tenant_expression}) "
        f"with check (organization_id = {tenant_expression})"
    )
    op.execute(
        """
        create function watchtower_private.validate_upload_session_completion()
        returns trigger
        language plpgsql
        set search_path = ''
        as $$
        begin
          if old.status <> 'pending' or new.status <> 'completed' then
            raise exception 'upload sessions only allow pending-to-completed transitions' using errcode = '55000';
          end if;
          if row(
            new.organization_id, new.assessment_id, new.provider, new.object_key,
            new.title, new.description, new.collection_method, new.source_type,
            new.source_identifier, new.observed_at, new.artifact_name, new.media_type,
            new.byte_size, new.sha256, new.sensitivity, new.normalized_facts,
            new.created_by, new.created_at, new.expires_at
          ) is distinct from row(
            old.organization_id, old.assessment_id, old.provider, old.object_key,
            old.title, old.description, old.collection_method, old.source_type,
            old.source_identifier, old.observed_at, old.artifact_name, old.media_type,
            old.byte_size, old.sha256, old.sensitivity, old.normalized_facts,
            old.created_by, old.created_at, old.expires_at
          ) then
            raise exception 'upload session provenance is immutable' using errcode = '55000';
          end if;
          return new;
        end
        $$
        """
    )
    op.execute(
        "create trigger evidence_upload_sessions_completion_only before update on evidence_upload_sessions "
        "for each row execute function watchtower_private.validate_upload_session_completion()"
    )
    op.execute("grant select, insert, update on evidence_upload_sessions to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")


def downgrade() -> None:
    """Remove direct-upload sessions and stored-object references."""
    op.drop_table("evidence_upload_sessions")
    op.execute("drop function watchtower_private.validate_upload_session_completion()")
    op.drop_constraint(
        "evidence_observations_artifact_object_key_unique",
        "evidence_observations",
        type_="unique",
    )
    op.drop_constraint(
        "evidence_observations_storage_fields_together",
        "evidence_observations",
        type_="check",
    )
    op.drop_constraint(
        "evidence_observations_byte_size_maximum",
        "evidence_observations",
        type_="check",
    )
    op.drop_constraint(
        "evidence_observations_storage_provider_allowed",
        "evidence_observations",
        type_="check",
    )
    op.drop_column("evidence_observations", "artifact_object_key")
    op.drop_column("evidence_observations", "storage_provider")
