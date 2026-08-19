"""Add server-backed user profile preferences.

Revision ID: 0006_user_preferences
Revises: 0005_automation_control_planes
Create Date: 2026-08-19
"""

# pylint: disable=invalid-name,no-member

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0006_user_preferences"
down_revision: str | None = "0005_automation_control_planes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Persist preferences globally per authenticated user with actor-level RLS."""
    op.execute(
        """
        create function watchtower_private.current_actor_id()
        returns uuid
        language sql
        stable
        set search_path = ''
        as $$
          select nullif(current_setting('watchtower.actor_id', true), '')::uuid
        $$
        """
    )
    op.create_table(
        "user_preferences",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("theme", sa.Text(), server_default="light", nullable=False),
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
            "theme in ('light', 'dark')",
            name="user_preferences_theme_allowed",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.execute("alter table user_preferences enable row level security")
    op.execute("alter table user_preferences force row level security")
    actor_expression = "(select watchtower_private.current_actor_id())"
    op.execute(
        "create policy user_preferences_actor_select on user_preferences "
        f"for select to watchtower_app using (user_id = {actor_expression})"
    )
    op.execute(
        "create policy user_preferences_actor_insert on user_preferences "
        f"for insert to watchtower_app with check (user_id = {actor_expression})"
    )
    op.execute(
        "create policy user_preferences_actor_update on user_preferences "
        f"for update to watchtower_app using (user_id = {actor_expression}) "
        f"with check (user_id = {actor_expression})"
    )
    op.execute("grant select, insert, update on user_preferences to watchtower_app")
    op.execute(
        "grant execute on function watchtower_private.current_actor_id() to watchtower_app"
    )


def downgrade() -> None:
    """Remove user preferences and actor context helper."""
    op.drop_table("user_preferences")
    op.execute("drop function watchtower_private.current_actor_id()")
