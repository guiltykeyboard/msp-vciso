"""Integration test fixtures for the tenant database and API."""

# Pytest resolves fixture parameters by reusing the fixture function name.
# pylint: disable=redefined-outer-name,too-many-instance-attributes

from collections.abc import Iterator
from dataclasses import dataclass
import os
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
import pytest


@dataclass(frozen=True, slots=True)
class SeedData:
    """Stable identifiers shared across isolation tests."""

    organization_a: UUID
    organization_b: UUID
    user_a: UUID
    user_b: UUID
    user_auditor: UUID
    framework_version_id: int
    assessment_a: UUID
    assessment_b: UUID


@pytest.fixture(scope="session")
def admin_url() -> str:
    """Return the administrative test database URL."""
    return os.environ["DATABASE_ADMIN_URL"]


@pytest.fixture(scope="session")
def runtime_url() -> str:
    """Return the RLS-constrained runtime database URL."""
    return os.environ["DATABASE_URL"]


@pytest.fixture(scope="session")
def seed_data(admin_url: str) -> Iterator[SeedData]:
    """Create two tenants with deliberately distinct users and assessments."""
    seed = SeedData(
        organization_a=UUID("10000000-0000-0000-0000-000000000001"),
        organization_b=UUID("20000000-0000-0000-0000-000000000002"),
        user_a=UUID("30000000-0000-0000-0000-000000000003"),
        user_b=UUID("40000000-0000-0000-0000-000000000004"),
        user_auditor=UUID("60000000-0000-0000-0000-000000000006"),
        framework_version_id=1,
        assessment_a=UUID("70000000-0000-0000-0000-000000000007"),
        assessment_b=UUID("80000000-0000-0000-0000-000000000008"),
    )
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(
            "truncate audit_events, evidence_upload_sessions, evidence_reviews, evidence_observations, "
            "assessments, organization_memberships, app_users, organizations, "
            "service_providers, framework_pack_versions restart identity cascade"
        )
        connection.execute(
            "insert into service_providers (id, name, slug) values (%s, 'Example MSP', 'example-msp')",
            (UUID("50000000-0000-0000-0000-000000000005"),),
        )
        with connection.cursor() as cursor:
            cursor.executemany(
                "insert into organizations (id, service_provider_id, name, slug) values (%s, %s, %s, %s)",
                [
                    (seed.organization_a, UUID("50000000-0000-0000-0000-000000000005"), "Tenant A", "tenant-a"),
                    (seed.organization_b, UUID("50000000-0000-0000-0000-000000000005"), "Tenant B", "tenant-b"),
                ],
            )
            cursor.executemany(
                "insert into app_users (id, external_subject, display_name) values (%s, %s, %s)",
                [
                    (seed.user_a, "test-user-a", "Test User A"),
                    (seed.user_b, "test-user-b", "Test User B"),
                    (seed.user_auditor, "test-auditor", "Test Auditor"),
                ],
            )
            cursor.executemany(
                "insert into organization_memberships (organization_id, user_id, role) values (%s, %s, 'customer_admin')",
                [
                    (seed.organization_a, seed.user_a),
                    (seed.organization_b, seed.user_b),
                ],
            )
            cursor.execute(
                "insert into organization_memberships (organization_id, user_id, role) values (%s, %s, 'auditor')",
                (seed.organization_a, seed.user_auditor),
            )
        connection.execute(
            """
            insert into framework_pack_versions (pack_key, version, sha256, content)
            values ('test-pack', '1.0.0', %s, '{}'::jsonb)
            """,
            ("a" * 64,),
        )
        with connection.cursor() as cursor:
            cursor.executemany(
                """
                insert into assessments (public_id, organization_id, framework_pack_version_id, name, created_by)
                values (%s, %s, %s, %s, %s)
                """,
                [
                    (seed.assessment_a, seed.organization_a, seed.framework_version_id, "Tenant A Assessment", seed.user_a),
                    (seed.assessment_b, seed.organization_b, seed.framework_version_id, "Tenant B Assessment", seed.user_b),
                ],
            )
    yield seed
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(
            "truncate audit_events, evidence_upload_sessions, evidence_reviews, evidence_observations, "
            "assessments, organization_memberships, app_users, organizations, "
            "service_providers, framework_pack_versions restart identity cascade"
        )


@pytest.fixture
def runtime_connection(runtime_url: str):
    """Open a connection as the least-privilege application login."""
    with psycopg.connect(runtime_url, row_factory=dict_row) as connection:
        yield connection
