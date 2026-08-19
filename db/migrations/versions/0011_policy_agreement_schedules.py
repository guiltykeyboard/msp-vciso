"""Add recurring review schedules to policy agreements.

Revision ID: 0011_policy_agreement_schedules
Revises: 0010_policy_acknowledgements
Create Date: 2026-08-19
"""

# pylint: disable=invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0011_policy_agreement_schedules"
down_revision: str | None = "0010_policy_acknowledgements"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Retain cadence metadata and link each completed cycle to its successor."""
    op.add_column(
        "policy_agreement_requests",
        sa.Column("recurrence_days", sa.Integer(), nullable=True),
    )
    op.add_column(
        "policy_agreement_requests",
        sa.Column(
            "prompt_before_days",
            sa.Integer(),
            server_default="14",
            nullable=False,
        ),
    )
    op.add_column(
        "policy_agreement_requests",
        sa.Column("next_review_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "policy_agreement_requests",
        sa.Column("schedule_basis", sa.Text(), nullable=True),
    )
    op.add_column(
        "policy_agreement_requests",
        sa.Column("superseded_by_request_id", sa.BigInteger(), nullable=True),
    )
    op.create_unique_constraint(
        "policy_agreement_requests_id_organization_unique",
        "policy_agreement_requests",
        ["id", "organization_id"],
    )
    op.create_check_constraint(
        "policy_agreement_requests_recurrence_range",
        "policy_agreement_requests",
        "recurrence_days is null or recurrence_days between 30 and 1095",
    )
    op.create_check_constraint(
        "policy_agreement_requests_prompt_range",
        "policy_agreement_requests",
        "prompt_before_days between 0 and 90",
    )
    op.create_check_constraint(
        "policy_agreement_requests_prompt_before_recurrence",
        "policy_agreement_requests",
        "recurrence_days is null or prompt_before_days < recurrence_days",
    )
    op.create_foreign_key(
        "policy_agreement_requests_successor_fk",
        "policy_agreement_requests",
        "policy_agreement_requests",
        ["superseded_by_request_id", "organization_id"],
        ["id", "organization_id"],
        ondelete="RESTRICT",
    )
    op.create_unique_constraint(
        "policy_agreement_requests_successor_unique",
        "policy_agreement_requests",
        ["superseded_by_request_id"],
    )
    op.create_index(
        "policy_agreement_requests_review_due_idx",
        "policy_agreement_requests",
        ["organization_id", "next_review_at"],
        postgresql_where=sa.text(
            "next_review_at is not null and superseded_by_request_id is null"
        ),
    )

    op.execute(
        """
        create or replace function watchtower_private.acknowledge_policy_agreement(
          token_id uuid, presented_hash bytea, typed_name text,
          connection_ip inet, browser_user_agent text
        ) returns table (
          acknowledgement_id uuid, signed_at timestamptz,
          signed_document_sha256 text, signed_version integer
        )
        language plpgsql security definer set search_path = '' as $$
        declare
          agreement public.policy_agreement_requests%rowtype;
          signer_id uuid;
          receipt public.policy_acknowledgements%rowtype;
          version_number integer;
        begin
          if length(trim(typed_name)) < 2 then
            return;
          end if;

          update public.policy_agreement_requests
          set status = 'acknowledged', acknowledged_at = now(),
              next_review_at = case
                when recurrence_days is null then null
                else now() + make_interval(days => recurrence_days)
              end
          where public_id = token_id
            and secret_hash = presented_hash
            and status = 'pending'
            and expires_at > now()
          returning * into agreement;

          if not found then
            return;
          end if;

          insert into public.app_users (external_subject, email, display_name)
          values (
            'policy-agreement:' || agreement.public_id::text,
            agreement.recipient_email,
            trim(typed_name)
          )
          on conflict (lower(email)) where email is not null
          do update set email = excluded.email
          returning id into signer_id;

          update public.policy_agreement_requests
          set acknowledged_by = signer_id
          where id = agreement.id;

          insert into public.policy_acknowledgements (
            organization_id, agreement_request_id, policy_document_id,
            policy_document_version_id, signer_user_id, signer_email,
            signer_display_name, attestation_text, document_sha256,
            identity_assurance, client_ip, user_agent
          ) values (
            agreement.organization_id, agreement.id, agreement.policy_document_id,
            agreement.policy_document_version_id, signer_id, agreement.recipient_email,
            trim(typed_name), agreement.attestation_text, agreement.document_sha256,
            'email_link', connection_ip, left(browser_user_agent, 1000)
          ) returning * into receipt;

          select versions.version_number into version_number
          from public.policy_document_versions versions
          where versions.id = agreement.policy_document_version_id;

          insert into public.audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
          ) values (
            agreement.organization_id, signer_id, 'policy.acknowledged',
            'policy_acknowledgement', receipt.public_id::text,
            jsonb_build_object(
              'agreement_request_id', agreement.public_id,
              'policy_document_version_id', agreement.policy_document_version_id,
              'version', version_number,
              'document_sha256', agreement.document_sha256,
              'identity_assurance', 'email_link',
              'next_review_at', agreement.next_review_at
            )
          );

          return query select receipt.public_id, receipt.acknowledged_at,
                              receipt.document_sha256, version_number;
        end
        $$
        """
    )


def downgrade() -> None:
    """Remove recurring review metadata and restore one-time acknowledgement."""
    op.execute(
        """
        create or replace function watchtower_private.acknowledge_policy_agreement(
          token_id uuid, presented_hash bytea, typed_name text,
          connection_ip inet, browser_user_agent text
        ) returns table (
          acknowledgement_id uuid, signed_at timestamptz,
          signed_document_sha256 text, signed_version integer
        )
        language plpgsql security definer set search_path = '' as $$
        declare
          agreement public.policy_agreement_requests%rowtype;
          signer_id uuid;
          receipt public.policy_acknowledgements%rowtype;
          version_number integer;
        begin
          if length(trim(typed_name)) < 2 then
            return;
          end if;

          update public.policy_agreement_requests
          set status = 'acknowledged', acknowledged_at = now()
          where public_id = token_id
            and secret_hash = presented_hash
            and status = 'pending'
            and expires_at > now()
          returning * into agreement;

          if not found then
            return;
          end if;

          insert into public.app_users (external_subject, email, display_name)
          values (
            'policy-agreement:' || agreement.public_id::text,
            agreement.recipient_email,
            trim(typed_name)
          )
          on conflict (lower(email)) where email is not null
          do update set email = excluded.email
          returning id into signer_id;

          update public.policy_agreement_requests
          set acknowledged_by = signer_id
          where id = agreement.id;

          insert into public.policy_acknowledgements (
            organization_id, agreement_request_id, policy_document_id,
            policy_document_version_id, signer_user_id, signer_email,
            signer_display_name, attestation_text, document_sha256,
            identity_assurance, client_ip, user_agent
          ) values (
            agreement.organization_id, agreement.id, agreement.policy_document_id,
            agreement.policy_document_version_id, signer_id, agreement.recipient_email,
            trim(typed_name), agreement.attestation_text, agreement.document_sha256,
            'email_link', connection_ip, left(browser_user_agent, 1000)
          ) returning * into receipt;

          select versions.version_number into version_number
          from public.policy_document_versions versions
          where versions.id = agreement.policy_document_version_id;

          insert into public.audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
          ) values (
            agreement.organization_id, signer_id, 'policy.acknowledged',
            'policy_acknowledgement', receipt.public_id::text,
            jsonb_build_object(
              'agreement_request_id', agreement.public_id,
              'policy_document_version_id', agreement.policy_document_version_id,
              'version', version_number,
              'document_sha256', agreement.document_sha256,
              'identity_assurance', 'email_link'
            )
          );

          return query select receipt.public_id, receipt.acknowledged_at,
                              receipt.document_sha256, version_number;
        end
        $$
        """
    )
    op.drop_index(
        "policy_agreement_requests_review_due_idx",
        table_name="policy_agreement_requests",
    )
    op.drop_constraint(
        "policy_agreement_requests_successor_unique",
        "policy_agreement_requests",
        type_="unique",
    )
    op.drop_constraint(
        "policy_agreement_requests_successor_fk",
        "policy_agreement_requests",
        type_="foreignkey",
    )
    op.drop_constraint(
        "policy_agreement_requests_id_organization_unique",
        "policy_agreement_requests",
        type_="unique",
    )
    op.drop_constraint(
        "policy_agreement_requests_prompt_before_recurrence",
        "policy_agreement_requests",
        type_="check",
    )
    op.drop_constraint(
        "policy_agreement_requests_prompt_range",
        "policy_agreement_requests",
        type_="check",
    )
    op.drop_constraint(
        "policy_agreement_requests_recurrence_range",
        "policy_agreement_requests",
        type_="check",
    )
    op.drop_column("policy_agreement_requests", "superseded_by_request_id")
    op.drop_column("policy_agreement_requests", "schedule_basis")
    op.drop_column("policy_agreement_requests", "next_review_at")
    op.drop_column("policy_agreement_requests", "prompt_before_days")
    op.drop_column("policy_agreement_requests", "recurrence_days")
