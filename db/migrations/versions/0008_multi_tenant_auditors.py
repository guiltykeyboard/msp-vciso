"""Expose only the current actor's active tenant memberships.

Revision ID: 0008_multi_tenant_auditors
Revises: 0007_tenant_invitations
Create Date: 2026-08-19
"""

# pylint: disable=invalid-name,no-member

from collections.abc import Sequence

from alembic import op


revision: str = "0008_multi_tenant_auditors"
down_revision: str | None = "0007_tenant_invitations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Allow an identity to discover only its own active tenant memberships."""
    op.execute(
        """
        create function watchtower_private.current_actor_organizations()
        returns table (
          organization_id uuid,
          organization_name text,
          organization_slug text,
          membership_role text
        )
        language sql security definer stable set search_path = '' as $$
          select organizations.id,
                 organizations.name,
                 organizations.slug,
                 memberships.role
          from public.organization_memberships as memberships
          join public.organizations as organizations
            on organizations.id = memberships.organization_id
          where memberships.user_id =
                  (select watchtower_private.current_actor_id())
            and memberships.status = 'active'
          order by organizations.name, organizations.id
        $$
        """
    )
    op.execute(
        "revoke all on function "
        "watchtower_private.current_actor_organizations() from public"
    )
    op.execute(
        "grant execute on function "
        "watchtower_private.current_actor_organizations() to watchtower_app"
    )


def downgrade() -> None:
    """Remove cross-tenant membership discovery."""
    op.execute(
        "drop function watchtower_private.current_actor_organizations()"
    )
