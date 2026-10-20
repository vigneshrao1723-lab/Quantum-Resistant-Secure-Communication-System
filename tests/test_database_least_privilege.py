"""
The server's runtime database login must be a least-privilege role.

Connects with the application's own configured DATABASE_URL (the same engine
the server uses) and proves, against the real PostgreSQL instance, what that
login can and cannot do. Every forbidden statement is refused by the database
itself, so none of them changes anything.
"""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from database.connection import engine


@pytest.fixture()
def conn():
    with engine.connect() as connection:
        yield connection
        connection.rollback()


def _refused(conn, statement):
    try:
        conn.execute(text(statement))
    except (ProgrammingError, DBAPIError):
        conn.rollback()
        return True
    conn.rollback()
    return False


def test_runtime_role_has_no_elevated_attributes(conn):
    row = conn.execute(text(
        "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
        "FROM pg_roles WHERE rolname = current_user"
    )).one()

    assert row.rolname == "qrscs_app"
    assert not any([row.rolsuper, row.rolcreatedb, row.rolcreaterole, row.rolreplication, row.rolbypassrls])


def test_runtime_role_cannot_change_the_schema(conn):
    assert _refused(conn, "CREATE TABLE qrscs_privilege_probe (x integer)")
    assert _refused(conn, "DROP TABLE users")
    assert _refused(conn, "ALTER TABLE users ADD COLUMN qrscs_probe integer")
    assert _refused(conn, "TRUNCATE TABLE messages")


def test_runtime_role_cannot_administer_the_server(conn):
    assert _refused(conn, "CREATE ROLE qrscs_probe_role")
    assert _refused(conn, "ALTER SYSTEM SET work_mem = '4MB'")
    assert _refused(conn, "CREATE DATABASE qrscs_probe_db")
    assert _refused(conn, "COPY (SELECT 1) TO PROGRAM 'echo probe'")


def test_runtime_role_cannot_see_migration_state(conn):
    assert _refused(conn, "SELECT * FROM alembic_version")


def test_runtime_role_can_still_do_everything_the_application_needs(conn):
    # DML on the application tables, inside a transaction that is rolled back.
    count = conn.execute(text("SELECT count(*) FROM users")).scalar_one()
    assert count >= 0
    conn.execute(text("DELETE FROM sessions WHERE false"))
    conn.execute(text("UPDATE messages SET id = id WHERE false"))
    conn.execute(text("SELECT pg_advisory_xact_lock(1)"))
