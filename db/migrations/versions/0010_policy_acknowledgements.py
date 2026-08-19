"""Add recipient-scoped policy acknowledgement records.

Revision ID: 0010_policy_acknowledgements
Revises: 0009_policy_procedure_library
Create Date: 2026-08-19
"""

# pylint: disable=invalid-name,no-member,duplicate-code

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0010_policy_acknowledgements"
down_revision: str | None = "0009_policy_procedure_library"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create version-pinned requests and immutable acknowledgement receipts."""
    op.create_unique_constraint(
        "policy_document_versions_identity_unique",
        "policy_document_versions",
        ["id", "policy_document_id", "organization_id"],
    )
    op.create_table(
        "policy_agreement_requests",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=False),
        sa.Column("policy_document_version_id", sa.BigInteger(), nullable=False),
        sa.Column("recipient_email", sa.Text(), nullable=False),
        sa.Column("recipient_display_name", sa.Text(), nullable=True),
        sa.Column("secret_hash", sa.LargeBinary(), nullable=False),
        sa.Column("document_sha256", sa.Text(), nullable=False),
        sa.Column("attestation_text", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("recipient_email = lower(recipient_email)", name="policy_agreement_requests_email_lowercase"),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="policy_agreement_requests_sha256_format"),
        sa.CheckConstraint("status in ('pending', 'acknowledged', 'revoked')", name="policy_agreement_requests_status_allowed"),
        sa.ForeignKeyConstraint(
            ["policy_document_id", "organization_id"],
            ["policy_documents.id", "policy_documents.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["policy_document_version_id", "policy_document_id", "organization_id"],
            ["policy_document_versions.id", "policy_document_versions.policy_document_id", "policy_document_versions.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["requested_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["revoked_by"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint(
            "id", "organization_id", "policy_document_id", "policy_document_version_id",
            name="policy_agreement_requests_identity_unique",
        ),
    )
    op.create_index(
        "policy_agreement_requests_pending_recipient_unique",
        "policy_agreement_requests",
        ["policy_document_version_id", "recipient_email"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "policy_agreement_requests_organization_created_idx",
        "policy_agreement_requests",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "policy_acknowledgements",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("agreement_request_id", sa.BigInteger(), nullable=False),
        sa.Column("policy_document_id", sa.BigInteger(), nullable=False),
        sa.Column("policy_document_version_id", sa.BigInteger(), nullable=False),
        sa.Column("signer_user_id", sa.Uuid(), nullable=False),
        sa.Column("signer_email", sa.Text(), nullable=False),
        sa.Column("signer_display_name", sa.Text(), nullable=False),
        sa.Column("attestation_text", sa.Text(), nullable=False),
        sa.Column("document_sha256", sa.Text(), nullable=False),
        sa.Column("identity_assurance", sa.Text(), nullable=False),
        sa.Column("client_ip", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("signer_email = lower(signer_email)", name="policy_acknowledgements_email_lowercase"),
        sa.CheckConstraint("document_sha256 ~ '^[0-9a-f]{64}$'", name="policy_acknowledgements_sha256_format"),
        sa.CheckConstraint("identity_assurance in ('email_link', 'oidc')", name="policy_acknowledgements_assurance_allowed"),
        sa.ForeignKeyConstraint(
            ["agreement_request_id", "organization_id", "policy_document_id", "policy_document_version_id"],
            ["policy_agreement_requests.id", "policy_agreement_requests.organization_id", "policy_agreement_requests.policy_document_id", "policy_agreement_requests.policy_document_version_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["signer_user_id"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
        sa.UniqueConstraint("agreement_request_id"),
    )

    tenant_expression = "(select watchtower_private.current_organization_id())"
    for table_name in ("policy_agreement_requests", "policy_acknowledgements"):
        op.execute(f"alter table {table_name} enable row level security")
        op.execute(f"alter table {table_name} force row level security")
        op.execute(
            f"create policy {table_name}_tenant_select on {table_name} for select "
            f"to watchtower_app using (organization_id = {tenant_expression})"
        )
    for action in ("insert", "update"):
        qualifier = "with check" if action == "insert" else "using"
        update_check = f" with check (organization_id = {tenant_expression})" if action == "update" else ""
        op.execute(
            f"create policy policy_agreement_requests_tenant_{action} on policy_agreement_requests "
            f"for {action} to watchtower_app {qualifier} "
            f"(organization_id = {tenant_expression}){update_check}"
        )

    op.execute(
        "create trigger policy_acknowledgements_immutable before update or delete on "
        "policy_acknowledgements for each row execute function watchtower_private.reject_immutable_change()"
    )
    op.execute("grant select, insert, update on policy_agreement_requests to watchtower_app")
    op.execute("grant select on policy_acknowledgements to watchtower_app")
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")

    op.execute(
        """
        create function watchtower_private.inspect_policy_agreement(
          token_id uuid, presented_hash bytea
        ) returns table (
          request_id uuid, organization_name text, document_title text,
          document_type text, version_number integer, document_content text,
          document_sha256 text, recipient_email text, recipient_display_name text,
          attestation_text text, agreement_status text, expires_at timestamptz,
          acknowledged_at timestamptz
        )
        language sql security definer stable set search_path = '' as $$
          select requests.public_id, organizations.name, documents.title,
                 documents.document_type, versions.version_number, versions.content,
                 requests.document_sha256, requests.recipient_email,
                 requests.recipient_display_name, requests.attestation_text,
                 requests.status, requests.expires_at, requests.acknowledged_at
          from public.policy_agreement_requests requests
          join public.organizations organizations on organizations.id = requests.organization_id
          join public.policy_documents documents on documents.id = requests.policy_document_id
          join public.policy_document_versions versions on versions.id = requests.policy_document_version_id
          where requests.public_id = token_id
            and requests.secret_hash = presented_hash
            and requests.status = 'pending'
            and requests.expires_at > now()
        $$
        """
    )
    op.execute(
        "revoke all on function watchtower_private.inspect_policy_agreement(uuid, bytea) from public"
    )
    op.execute(
        "grant execute on function watchtower_private.inspect_policy_agreement(uuid, bytea) to watchtower_app"
    )

    op.execute(
        """
        create function watchtower_private.acknowledge_policy_agreement(
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
    op.execute(
        "revoke all on function watchtower_private.acknowledge_policy_agreement(uuid, bytea, text, inet, text) from public"
    )
    op.execute(
        "grant execute on function watchtower_private.acknowledge_policy_agreement(uuid, bytea, text, inet, text) to watchtower_app"
    )


def downgrade() -> None:
    """Remove acknowledgement receipts, requests, and their token functions."""
    op.execute(
        "drop function watchtower_private.acknowledge_policy_agreement(uuid, bytea, text, inet, text)"
    )
    op.execute("drop function watchtower_private.inspect_policy_agreement(uuid, bytea)")
    op.drop_table("policy_acknowledgements")
    op.drop_table("policy_agreement_requests")
    op.drop_constraint(
        "policy_document_versions_identity_unique",
        "policy_document_versions",
        type_="unique",
    )
