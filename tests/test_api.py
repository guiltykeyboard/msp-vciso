"""HTTP tests for health and tenant authorization behavior."""

from fastapi.testclient import TestClient

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def test_health_endpoints(seed_data) -> None:
    """The API exposes separate liveness and dependency readiness checks."""
    del seed_data
    with TestClient(app) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ready"}


def test_api_lists_only_the_authorized_tenant(seed_data) -> None:
    """A valid membership sees its organization and no neighboring assessment."""
    with TestClient(app) as client:
        response = client.get(
            "/v1/assessments",
            headers=_headers(seed_data.organization_a, seed_data.user_a),
        )

    assert response.status_code == 200
    assert [assessment["name"] for assessment in response.json()] == ["Tenant A Assessment"]


def test_api_rejects_actor_without_tenant_membership(seed_data) -> None:
    """Selecting a tenant header does not establish authority by itself."""
    with TestClient(app) as client:
        response = client.get(
            "/v1/assessments",
            headers=_headers(seed_data.organization_a, seed_data.user_b),
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "No active membership for this organization"


def test_api_prevents_auditor_from_creating_assessment(seed_data) -> None:
    """A read-only tenant role cannot create an assessment."""
    with TestClient(app) as client:
        response = client.post(
            "/v1/assessments",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
            json={
                "framework_pack_version_id": seed_data.framework_version_id,
                "name": "Auditor Write Attempt",
            },
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "This tenant role cannot create assessments"
