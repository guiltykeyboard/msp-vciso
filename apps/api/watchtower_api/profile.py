"""Authenticated user profile preference routes."""

from fastapi import APIRouter

from watchtower_api.database import TenantDatabaseSession
from watchtower_api.models import UserPreferencesResponse, UserPreferencesUpdate


router = APIRouter(prefix="/v1/profile", tags=["profile"])


@router.get(
    "/preferences",
    response_model=UserPreferencesResponse,
    summary="Get the current user's preferences",
    operation_id="getCurrentUserPreferences",
)
async def get_preferences(session: TenantDatabaseSession) -> UserPreferencesResponse:
    """Return global preferences for the authenticated user, independent of tenant."""
    cursor = await session.connection.execute(
        "select theme, updated_at from user_preferences where user_id = %s",
        (session.identity.actor_id,),
    )
    preferences = await cursor.fetchone()
    if preferences is None:
        return UserPreferencesResponse(theme="light", updated_at=None)
    return UserPreferencesResponse.model_validate(preferences)


@router.put(
    "/preferences",
    response_model=UserPreferencesResponse,
    summary="Update the current user's preferences",
    operation_id="updateCurrentUserPreferences",
)
async def update_preferences(
    payload: UserPreferencesUpdate,
    session: TenantDatabaseSession,
) -> UserPreferencesResponse:
    """Upsert the authenticated user's server-backed profile preferences."""
    cursor = await session.connection.execute(
        """
        insert into user_preferences (user_id, theme)
        values (%s, %s)
        on conflict (user_id) do update
        set theme = excluded.theme, updated_at = now()
        returning theme, updated_at
        """,
        (session.identity.actor_id, payload.theme),
    )
    return UserPreferencesResponse.model_validate(await cursor.fetchone())
