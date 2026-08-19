"""Add tenant-scoped client access invitations.

Revision ID: 0007_tenant_invitations
Revises: 0006_user_preferences
Create Date: 2026-08-19
"""

# pylint: disable=invalid-name,no-member,duplicate-code

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0007_tenant_invitations"
down_revision: str | None = "0006_user_preferences"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create invitation state, tenant policies, and atomic token acceptance."""
    op.create_index(
        "app_users_email_ci_unique",
        "app_users",
        [sa.text("lower(email)")],
        unique=True,
        postgresql_where=sa.text("email is not null"),
    )
    op.create_table(
        "organization_invitations",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column(
            "public_id",
            sa.Uuid(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("secret_hash", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("invited_by", sa.Uuid(), nullable=False),
        sa.Column("accepted_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column(
            "expires_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("email = lower(email)", name="organization_invitations_email_lowercase"),
        sa.CheckConstraint(
            "role in ('customer_admin', 'control_owner', 'reviewer', 'auditor')",
            name="organization_invitations_role_allowed",
        ),
        sa.CheckConstraint(
            "status in ('pending', 'accepted', 'revoked')",
            name="organization_invitations_status_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["invited_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["accepted_by"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["revoked_by"], ["app_users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id"),
    )
    op.create_index(
        "organization_invitations_pending_email_unique",
        "organization_invitations",
        ["organization_id", "email"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "organization_invitations_organization_created_idx",
        "organization_invitations",
        ["organization_id", "created_at"],
    )

    tenant_expression = "(select watchtower_private.current_organization_id())"
    op.execute("alter table organization_invitations enable row level security")
    op.execute("alter table organization_invitations force row level security")
    for action in ("select", "insert", "update"):
        qualifier = "using" if action in {"select", "update"} else "with check"
        update_check = (
            f" with check (organization_id = {tenant_expression})"
            if action == "update"
            else ""
        )
        op.execute(
            f"create policy organization_invitations_tenant_{action} "
            f"on organization_invitations for {action} to watchtower_app "
            f"{qualifier} (organization_id = {tenant_expression}){update_check}"
        )
    op.execute(
        "grant select, insert, update on organization_invitations to watchtower_app"
    )
    op.execute("grant usage, select on all sequences in schema public to watchtower_app")

    op.execute(
        """
        create function watchtower_private.accept_organization_invitation(
          token_id uuid, presented_hash bytea, invitee_display_name text
        ) returns table (
          accepted_organization_id uuid,
          accepted_user_id uuid,
          accepted_role text
        )
        language plpgsql security definer set search_path = '' as $$
        declare
          invitation public.organization_invitations%rowtype;
          resolved_user_id uuid;
        begin
          update public.organization_invitations
          set status = 'accepted', accepted_at = now()
          where public_id = token_id
            and secret_hash = presented_hash
            and status = 'pending'
            and expires_at > now()
          returning * into invitation;

          if not found then
            return;
          end if;

          insert into public.app_users (external_subject, email, display_name)
          values (
            'invitation:' || invitation.public_id::text,
            invitation.email,
            invitee_display_name
          )
          on conflict (lower(email)) where email is not null
          do update set email = excluded.email
          returning id into resolved_user_id;

          insert into public.organization_memberships (
            organization_id, user_id, role, status
          ) values (
            invitation.organization_id, resolved_user_id, invitation.role, 'active'
          )
          on conflict (organization_id, user_id)
          do update set role = excluded.role, status = 'active';

          update public.organization_invitations
          set accepted_by = resolved_user_id
          where id = invitation.id;

          insert into public.audit_events (
            organization_id, actor_id, event_type, target_type, target_id, details
          ) values (
            invitation.organization_id,
            resolved_user_id,
            'invitation.accepted',
            'organization_invitation',
            invitation.public_id::text,
            jsonb_build_object('role', invitation.role)
          );

          return query select invitation.organization_id, resolved_user_id, invitation.role;
        end
        $$
        """
    )
    op.execute(
        "revoke all on function "
        "watchtower_private.accept_organization_invitation(uuid, bytea, text) from public"
    )
    op.execute(
        "grant execute on function "
        "watchtower_private.accept_organization_invitation(uuid, bytea, text) "
        "to watchtower_app"
    )
    op.execute(
        """
        create function watchtower_private.organization_has_member_email(
          requested_organization_id uuid, requested_email text
        ) returns boolean
        language sql security definer stable set search_path = '' as $$
          select
            requested_organization_id =
              (select watchtower_private.current_organization_id())
            and exists (
              select 1
              from public.organization_memberships memberships
              join public.app_users users on users.id = memberships.user_id
              where memberships.organization_id = requested_organization_id
                and memberships.status = 'active'
                and lower(users.email) = requested_email
            )
        $$
        """
    )
    op.execute(
        "revoke all on function "
        "watchtower_private.organization_has_member_email(uuid, text) from public"
    )
    op.execute(
        "grant execute on function "
        "watchtower_private.organization_has_member_email(uuid, text) to watchtower_app"
    )


def downgrade() -> None:
    """Remove client invitations and their acceptance function."""
    op.execute(
        "drop function watchtower_private.organization_has_member_email(uuid, text)"
    )
    op.execute(
        "drop function "
        "watchtower_private.accept_organization_invitation(uuid, bytea, text)"
    )
    op.drop_table("organization_invitations")
    op.drop_index("app_users_email_ci_unique", table_name="app_users")
