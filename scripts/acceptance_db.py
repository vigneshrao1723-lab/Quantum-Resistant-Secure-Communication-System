"""Create / drop the isolated PostgreSQL database used by acceptance testing.

    python scripts/acceptance_db.py create   # (re)create the database and migrate it
    python scripts/acceptance_db.py drop     # remove it

The acceptance database (``qrscs_accept`` by default) is separate from the
development database. It has the same least-privilege layout as production:

* owned by ``qrscs_migrator`` (the role Alembic uses);
* ``qrscs_app`` (the role the server uses) gets DML on the application tables
  and sequences only -- no DDL, and no access to ``alembic_version``.

The role passwords are the ones already configured in ``.env``; they are read
here and handed to child processes through their environment. Nothing secret is
printed. The administrator credential comes from the same places
``setup_database_roles.py`` uses and is needed only to create / drop the database.

Other modules can ``import acceptance_db`` and call ``urls()`` to obtain the
application / migration URLs for the acceptance database.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

import setup_database_roles as roles  # noqa: E402

DEFAULT_DB = os.environ.get("QRSCS_ACCEPTANCE_DB", "qrscs_accept")


def _env_text() -> str:
    return roles.ENV_PATH.read_text(encoding="utf-8")


def urls(dbname: str = DEFAULT_DB) -> tuple[str, str]:
    """(application URL, migration URL) pointing at the acceptance database."""
    text = _env_text()
    out = []
    for key in ("DATABASE_URL", "MIGRATION_DATABASE_URL"):
        value = roles._read_env_value(text, key)
        if not value:
            raise RuntimeError(f"{key} is not set in .env; run scripts/setup_database_roles.py first")
        p = roles._parts(value)
        out.append(roles._url(p["user"], p["password"], p["host"], p["port"], dbname))
    return out[0], out[1]


def _admin():
    url, _ = roles._load_admin_url(_env_text())
    if not url:
        raise RuntimeError("no administrator credential (see setup_database_roles.py)")
    return roles._parts(url)


def drop(dbname: str = DEFAULT_DB) -> None:
    admin = _admin()
    conn = roles._connect(admin, "postgres")
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(dbname)))
    cur.close()
    conn.close()


def create(dbname: str = DEFAULT_DB) -> None:
    admin = _admin()
    ident = sql.Identifier
    drop(dbname)
    conn = roles._connect(admin, "postgres")
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(ident(dbname), ident(roles.MIGRATOR_ROLE)))
    cur.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(ident(dbname)))
    cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(ident(dbname), ident(roles.APP_ROLE)))
    cur.close()
    conn.close()

    app_url, migration_url = urls(dbname)

    # Schema + default privileges inside the new database, as its owner.
    mig = roles._parts(migration_url)
    conn = roles._connect(mig, dbname)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(sql.SQL("REVOKE ALL ON SCHEMA public FROM PUBLIC"))
    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(ident(roles.APP_ROLE)))
    cur.execute(sql.SQL(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(ident(roles.MIGRATOR_ROLE), ident(roles.APP_ROLE)))
    cur.execute(sql.SQL(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
        "GRANT USAGE, SELECT ON SEQUENCES TO {}").format(ident(roles.MIGRATOR_ROLE), ident(roles.APP_ROLE)))
    cur.close()
    conn.close()

    env = dict(os.environ, MIGRATION_DATABASE_URL=migration_url, DATABASE_URL=app_url)
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, check=True)

    # Default privileges grant DML on every new table, alembic_version included;
    # the runtime role must not touch migration bookkeeping.
    conn = roles._connect(mig, dbname)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(sql.SQL("REVOKE ALL ON TABLE public.alembic_version FROM {}").format(ident(roles.APP_ROLE)))
    cur.close()
    conn.close()

    # The application role must have been given the tables by default privileges,
    # and must not be able to change the schema or read alembic_version.
    app = roles._parts(app_url)
    conn = roles._connect(app, dbname)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM users")
    for statement, label in (
        ("CREATE TABLE _x(a int)", "DDL"),
        ("SELECT * FROM alembic_version", "alembic_version"),
        ("TRUNCATE users", "TRUNCATE"),
    ):
        try:
            cur.execute(statement)
        except psycopg2.errors.InsufficientPrivilege:
            continue
        raise RuntimeError(f"application role unexpectedly allowed: {label}")
    cur.close()
    conn.close()
    print(f"acceptance database '{dbname}' ready (migrated, least-privilege verified)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("create", "drop"))
    ap.add_argument("--db", default=DEFAULT_DB)
    args = ap.parse_args(argv)
    if args.db in ("qrscs", "postgres"):
        print("refusing to touch the development/maintenance database", file=sys.stderr)
        return 2
    (create if args.action == "create" else drop)(args.db)
    if args.action == "drop":
        print(f"acceptance database '{args.db}' dropped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
