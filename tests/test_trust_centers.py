"""Public trust center, custom-domain, and disclosure-boundary tests."""

# Test helpers intentionally mirror the public policy lifecycle setup.
# pylint: disable=duplicate-code

from fastapi.testclient import TestClient
import psycopg

from watchtower_api.main import app


def _headers(organization_id, actor_id) -> dict[str, str]:
    return {
        "X-Watchtower-Organization": str(organization_id),
        "X-Watchtower-Actor": str(actor_id),
    }


def _profile(client: TestClient, seed_data, status: str = "published"):
    return client.put(
        "/v1/trust-center",
        headers=_headers(seed_data.organization_a, seed_data.user_a),
        json={
            "display_name": "Tenant A Security",
            "headline": "Security and compliance are shared responsibilities.",
            "overview": "Tenant A publishes reviewed assurance information for partners.",
            "security_contact_email": "SECURITY@TENANT-A.EXAMPLE",
            "primary_color": "#14532D",
            "status": status,
        },
    )


def _approved_policy(client: TestClient, seed_data):
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    created = client.post(
        "/v1/policies",
        headers=headers,
        json={
            "title": "Public Information Security Policy",
            "document_type": "policy",
            "content": "CONFIDENTIAL IMPLEMENTATION DETAIL THAT MUST NEVER BE PUBLIC",
        },
    )
    client.put(
        f"/v1/policies/{created.json()['id']}/status",
        headers=headers,
        json={"status": "approved"},
    )
    return created.json()


def test_published_profile_is_public_by_slug_without_tenant_headers(seed_data) -> None:
    """Drafts fail closed while published profiles resolve through a stable preview URL."""
    with TestClient(app) as client:
        draft = _profile(client, seed_data, "draft")
        hidden = client.get("/v1/public/trust?slug=tenant-a")
        published = _profile(client, seed_data)
        visible = client.get("/v1/public/trust?slug=tenant-a")

    assert draft.status_code == 200
    assert hidden.status_code == 404
    assert published.json()["profile"]["security_contact_email"] == "security@tenant-a.example"
    assert visible.status_code == 200
    assert visible.headers["cache-control"] == "public, max-age=300"
    assert visible.json()["display_name"] == "Tenant A Security"
    assert "organization_id" not in visible.json()


def test_only_approved_pinned_policy_metadata_is_disclosed(seed_data) -> None:
    """A public resource never exposes the underlying policy body or evidence."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    with TestClient(app) as client:
        _profile(client, seed_data)
        policy = _approved_policy(client, seed_data)
        resource = client.post(
            "/v1/trust-center/resources",
            headers=headers,
            json={
                "policy_document_id": policy["id"],
                "public_title": "Information Security Program",
                "public_summary": "Our program is reviewed and approved by leadership.",
                "category": "assurance",
            },
        )
        public = client.get("/v1/public/trust?slug=tenant-a")

    assert resource.status_code == 201
    assert resource.json()["version"] == 1
    serialized = public.text
    assert "Information Security Program" in serialized
    assert "CONFIDENTIAL IMPLEMENTATION DETAIL" not in serialized
    assert "content" not in public.json()["resources"][0]


def test_custom_domain_requires_txt_cname_and_can_be_disabled(seed_data, monkeypatch) -> None:
    """TLS authorization is impossible until both ownership and routing are verified."""
    headers = _headers(seed_data.organization_a, seed_data.user_a)
    authorization = "token=watchtower_trust_tls_development_secret"

    async def matching_txt(_name: str) -> set[str]:
        return {domain.json()["verification_record_value"]}

    async def matching_cname(_name: str) -> str:
        return "trust.localhost"

    with TestClient(app) as client:
        _profile(client, seed_data)
        domain = client.post(
            "/v1/trust-center/domains",
            headers=headers,
            json={"hostname": "Trust.Tenant-A.Example", "tls_provider": "caddy_acme"},
        )
        denied_before_verification = client.get(
            f"/v1/internal/trust-domains:authorize?domain=trust.tenant-a.example&{authorization}"
        )
        monkeypatch.setattr("watchtower_api.trust_centers.lookup_txt", matching_txt)
        verified = client.post(
            f"/v1/trust-center/domains/{domain.json()['id']}:verify",
            headers=headers,
        )
        monkeypatch.setattr("watchtower_api.trust_centers.lookup_cname", matching_cname)
        activated = client.post(
            f"/v1/trust-center/domains/{domain.json()['id']}:activate",
            headers=headers,
        )
        authorized = client.get(
            f"/v1/internal/trust-domains:authorize?domain=trust.tenant-a.example&{authorization}"
        )
        denied_with_wrong_secret = client.get(
            "/v1/internal/trust-domains:authorize?domain=trust.tenant-a.example&token=wrong"
        )
        public = client.get(
            "/v1/public/trust",
            headers={"host": "trust.tenant-a.example"},
        )
        disabled = client.post(
            f"/v1/trust-center/domains/{domain.json()['id']}:disable",
            headers=headers,
        )
        denied_after_disable = client.get(
            f"/v1/internal/trust-domains:authorize?domain=trust.tenant-a.example&{authorization}"
        )

    assert domain.status_code == 201
    assert domain.json()["hostname"] == "trust.tenant-a.example"
    assert denied_before_verification.status_code == 404
    assert verified.json()["status"] == "verified"
    assert activated.json()["status"] == "active"
    assert activated.json()["certificate_status"] == "provisioning"
    assert authorized.status_code == 200
    assert denied_with_wrong_secret.status_code == 404
    assert public.status_code == 200
    assert disabled.json()["status"] == "disabled"
    assert denied_after_disable.status_code == 404


def test_trust_management_is_tenant_isolated_admin_only_and_audited(seed_data, admin_url) -> None:
    """Auditors can review configuration but cannot publish or alter it."""
    with TestClient(app) as client:
        _profile(client, seed_data)
        tenant_b = client.get(
            "/v1/trust-center",
            headers=_headers(seed_data.organization_b, seed_data.user_b),
        )
        auditor_read = client.get(
            "/v1/trust-center",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
        )
        auditor_write = client.put(
            "/v1/trust-center",
            headers=_headers(seed_data.organization_a, seed_data.user_auditor),
            json={
                "display_name": "Unauthorized",
                "headline": "Unauthorized change",
                "overview": "This must not be saved.",
                "primary_color": "#14532d",
                "status": "published",
            },
        )

    assert tenant_b.json()["profile"] is None
    assert auditor_read.json()["profile"]["display_name"] == "Tenant A Security"
    assert auditor_write.status_code == 403
    with psycopg.connect(admin_url) as connection:
        events = connection.execute(
            "select count(*) from audit_events where event_type like 'trust_center.%'"
        ).fetchone()[0]
    assert events >= 1
