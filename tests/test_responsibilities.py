"""Tenant role catalog and shared-responsibility matrix tests."""

from fastapi.testclient import TestClient
import psycopg

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def _role(client: TestClient, seed_data, name: str, party: str = "customer"):
    return client.post(
        "/v1/responsibility-roles",
        headers=_headers(seed_data.organization_a, seed_data.user_a),
        json={"name": name, "description": f"{name} duties", "party": party},
    )


def _policy(client: TestClient, seed_data):
    return client.post(
        "/v1/policies",
        headers=_headers(seed_data.organization_a, seed_data.user_a),
        json={"title": "Incident Response Policy", "document_type": "policy", "content": "Respond to security incidents."},
    ).json()


def test_role_holder_and_policy_raci_are_audited(seed_data, admin_url) -> None:
    """Admins can document people and accountability without granting access."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        policy = _policy(client, seed_data)
        role = _role(client, seed_data, "Information Security Officer")
        holder = client.post(
            f"/v1/responsibility-roles/{role.json()['id']}/holders",
            headers=headers,
            json={
                "display_name": "Alex Security",
                "email": "ALEX.SECURITY@example.gov",
                "is_primary": True,
            },
        )
        assignment = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={
                "role_id": role.json()["id"],
                "target_type": "policy",
                "policy_document_id": policy["id"],
                "raci": "accountable",
                "delivery_model": "customer",
                "notes": "Approves and reviews the policy.",
            },
        )
        matrix = client.get("/v1/responsibilities", headers=headers)

    assert role.status_code == 201
    assert holder.status_code == 201
    assert holder.json()["email"] == "alex.security@example.gov"
    assert holder.json()["app_user_id"] is None
    assert assignment.status_code == 201
    assert assignment.json()["target_title"] == "Incident Response Policy"
    assert matrix.json()["roles"][0]["holders"][0]["display_name"] == "Alex Security"
    assert matrix.json()["assignments"][0]["raci"] == "accountable"

    with psycopg.connect(admin_url) as connection:
        membership = connection.execute(
            "select count(*) from organization_memberships memberships join app_users users on users.id = memberships.user_id where lower(users.email) = 'alex.security@example.gov'"
        ).fetchone()[0]
        events = connection.execute(
            "select event_type from audit_events where event_type like 'responsibility.%%' order by occurred_at, id"
        ).fetchall()
    assert membership == 0
    assert [event[0] for event in events] == [
        "responsibility.role_created",
        "responsibility.holder_assigned",
        "responsibility.assignment_created",
    ]


def test_shared_delivery_supports_multiple_responsible_roles_but_one_accountable(seed_data) -> None:
    """Shared work can have several doers while retaining one accountable owner."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        policy = _policy(client, seed_data)
        customer_role = _role(client, seed_data, "Customer IT Manager")
        msp_role = _role(client, seed_data, "MSP Security Operations", "msp")
        payload = {
            "target_type": "policy",
            "policy_document_id": policy["id"],
            "delivery_model": "shared",
        }
        customer_responsible = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={**payload, "role_id": customer_role.json()["id"], "raci": "responsible"},
        )
        msp_responsible = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={**payload, "role_id": msp_role.json()["id"], "raci": "responsible"},
        )
        accountable = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={**payload, "role_id": customer_role.json()["id"], "raci": "accountable"},
        )
        second_accountable = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={**payload, "role_id": msp_role.json()["id"], "raci": "accountable"},
        )

    assert customer_responsible.status_code == 201
    assert msp_responsible.status_code == 201
    assert accountable.status_code == 201
    assert second_accountable.status_code == 409


def test_control_mapping_is_limited_to_tenant_assessments(seed_data, admin_url) -> None:
    """A role can map only to controls present in the active tenant's frameworks."""
    with psycopg.connect(admin_url) as connection:
        connection.execute(
            """
            update framework_pack_versions
            set content = '{"requirements":[{"id":"CJIS-AT-2","title":"Literacy Training and Awareness"}]}'::jsonb
            where id = %s
            """,
            (seed_data.framework_version_id,),
        )
        connection.commit()
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        role = _role(client, seed_data, "Training Coordinator")
        valid = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={
                "role_id": role.json()["id"],
                "target_type": "control",
                "framework_pack_version_id": seed_data.framework_version_id,
                "control_reference": "CJIS-AT-2",
                "raci": "responsible",
                "delivery_model": "shared",
            },
        )
        invalid = client.post(
            "/v1/responsibility-assignments",
            headers=headers,
            json={
                "role_id": role.json()["id"],
                "target_type": "control",
                "framework_pack_version_id": seed_data.framework_version_id,
                "control_reference": "NOT-A-CONTROL",
                "raci": "responsible",
                "delivery_model": "customer",
            },
        )

    assert valid.status_code == 201
    assert valid.json()["framework"].endswith(" 1.0.0")
    assert invalid.status_code == 422


def test_responsibilities_are_tenant_isolated_and_admin_managed(seed_data) -> None:
    """Other tenants see no rows and read-only personnel cannot mutate the matrix."""
    with TestClient(app) as client:
        created = _role(client, seed_data, "Privacy Officer")
        foreign = client.get(
            "/v1/responsibilities",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )
        rejected = client.post(
            "/v1/responsibility-roles",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
            json={"name": "Unauthorized Role", "party": "customer"},
        )
        auditor_read = client.get(
            "/v1/responsibilities",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
        )

    assert created.status_code == 201
    assert foreign.json()["roles"] == []
    assert foreign.json()["assignments"] == []
    assert rejected.status_code == 403
    assert "Privacy Officer" in {role["name"] for role in auditor_read.json()["roles"]}
