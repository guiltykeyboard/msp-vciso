"""User profile preference persistence and isolation tests."""

from fastapi.testclient import TestClient
import psycopg

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def test_theme_preference_persists_across_clients(seed_data, admin_url) -> None:
    """A saved dark theme is returned to a later browser-like API client."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with psycopg.connect(admin_url) as connection:
        connection.execute(
            "delete from user_preferences where user_id = %s",
            (seed_data.user_a,),
        )

    with TestClient(app) as client:
        default_response = client.get("/v1/profile/preferences", headers=headers)
        update_response = client.put(
            "/v1/profile/preferences",
            headers=headers,
            json={"theme": "dark"},
        )

    assert default_response.status_code == 200
    assert default_response.json() == {"theme": "light", "updated_at": None}
    assert update_response.status_code == 200
    assert update_response.json()["theme"] == "dark"
    assert update_response.json()["updated_at"] is not None

    with TestClient(app) as later_client:
        persisted_response = later_client.get("/v1/profile/preferences", headers=headers)

    assert persisted_response.status_code == 200
    assert persisted_response.json()["theme"] == "dark"


def test_theme_preference_rejects_unknown_value(seed_data) -> None:
    """The API contract permits only implemented light and dark themes."""
    with TestClient(app) as client:
        response = client.put(
            "/v1/profile/preferences",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
            json={"theme": "browser-cookie"},
        )

    assert response.status_code == 422


def test_user_preferences_are_actor_isolated(seed_data, runtime_connection) -> None:
    """Actor-level RLS prevents another valid user from reading or changing a profile."""
    runtime_connection.execute(
        "select set_config('watchtower.organization_id', %s, true)",
        (str(seed_data.organization_b),),
    )
    runtime_connection.execute(
        "select set_config('watchtower.actor_id', %s, true)",
        (str(seed_data.user_b),),
    )

    hidden = runtime_connection.execute(
        "select theme from user_preferences where user_id = %s",
        (seed_data.user_a,),
    ).fetchall()
    update = runtime_connection.execute(
        "update user_preferences set theme = 'light' where user_id = %s",
        (seed_data.user_a,),
    )

    assert hidden == []
    assert update.rowcount == 0
