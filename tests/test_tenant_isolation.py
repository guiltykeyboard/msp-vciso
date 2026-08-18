"""Negative tests proving PostgreSQL-enforced tenant isolation."""

import psycopg
import pytest


def _set_tenant(connection: psycopg.Connection, organization_id) -> None:
    connection.execute(
        "select set_config('watchtower.organization_id', %s, true)",
        (str(organization_id),),
    )


def test_no_context_returns_no_tenant_rows(runtime_connection, seed_data) -> None:
    """Runtime credentials alone confer no organization access."""
    del seed_data
    rows = runtime_connection.execute("select id from organizations").fetchall()
    assert rows == []


def test_context_only_exposes_one_tenant(runtime_connection, seed_data) -> None:
    """The database filters unqualified selects to the active tenant."""
    with runtime_connection.transaction():
        _set_tenant(runtime_connection, seed_data.organization_a)
        organizations = runtime_connection.execute("select id from organizations").fetchall()
        assessments = runtime_connection.execute("select name from assessments order by name").fetchall()

    assert organizations == [{"id": seed_data.organization_a}]
    assert assessments == [{"name": "Tenant A Assessment"}]


def test_cross_tenant_insert_is_rejected(runtime_connection, seed_data) -> None:
    """WITH CHECK prevents a write targeting another organization."""
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with runtime_connection.transaction():
            _set_tenant(runtime_connection, seed_data.organization_a)
            runtime_connection.execute(
                """
                insert into assessments (
                    organization_id, framework_pack_version_id, name, created_by
                ) values (%s, %s, 'Forbidden Assessment', %s)
                """,
                (
                    seed_data.organization_b,
                    seed_data.framework_version_id,
                    seed_data.user_a,
                ),
            )


def test_tenant_context_does_not_leak_between_transactions(runtime_connection, seed_data) -> None:
    """SET LOCAL context disappears before a pooled connection is reused."""
    with runtime_connection.transaction():
        _set_tenant(runtime_connection, seed_data.organization_a)
        assert runtime_connection.execute("select count(*) as count from assessments").fetchone()["count"] == 1

    with runtime_connection.transaction():
        assert runtime_connection.execute("select count(*) as count from assessments").fetchone()["count"] == 0


def test_audit_events_are_append_only(admin_url, seed_data) -> None:
    """Even administrative SQL cannot silently rewrite an audit event."""
    with psycopg.connect(admin_url) as connection:
        event_id = connection.execute(
            """
            insert into audit_events (
                organization_id, actor_id, event_type, target_type, target_id
            ) values (%s, %s, 'assessment.created', 'assessment', '1')
            returning id
            """,
            (seed_data.organization_a, seed_data.user_a),
        ).fetchone()[0]
        connection.commit()
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            connection.execute("update audit_events set event_type = 'rewritten' where id = %s", (event_id,))
