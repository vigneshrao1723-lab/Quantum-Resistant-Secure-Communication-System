"""
Create the least-privilege PostgreSQL roles QRSCS runs with.

    python scripts/setup_database_roles.py            # idempotent
    python scripts/setup_database_roles.py --rotate   # also issue new passwords

Roles
-----
qrscs_app       Runtime role the chat server connects as (DATABASE_URL).
                LOGIN only: no superuser, createdb, createrole, replication or
                row-security bypass. SELECT/INSERT/UPDATE/DELETE on the
                application tables and USAGE/SELECT on their sequences --
                nothing else (no DDL, no TRUNCATE, no access to
                alembic_version).
qrscs_migrator  Owns the database and every table/sequence in it, and is what
                Alembic connects as (MIGRATION_DATABASE_URL). Not superuser.
                Tables it creates in future are granted to qrscs_app
                automatically (ALTER DEFAULT PRIVILEGES).

The administrator (superuser) credential is needed only by this script. It is
read from, in order: the QRSCS_ADMIN_DATABASE_URL environment variable, then
~/.qrscs/admin.env (outside the repository, so it is never archived with the
project), then -- once, on first run -- the project .env's DATABASE_URL if that
is still a superuser; in that case it is moved to ~/.qrscs/admin.env and
removed from .env.

No password is ever printed. New passwords are written only to .env.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import psycopg2
from psycopg2 import sql

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
ADMIN_FILE = Path.home() / ".qrscs" / "admin.env"
ADMIN_KEY = "QRSCS_ADMIN_DATABASE_URL"
APP_ROLE = "qrscs_app"
MIGRATOR_ROLE = "qrscs_migrator"


# --------------------------------------------------------------- .env helpers

def _read_env_value(text: str, key: str):
    m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.*?)\s*$", text, re.M)
    return m.group(1).strip("'\"") if m else None


def _set_env_value(text: str, key: str, value: str) -> str:
    newline = "\r\n" if "\r\n" in text else "\n"
    pattern = re.compile(rf"^(\s*{re.escape(key)}\s*=).*$", re.M)
    if pattern.search(text):
        return pattern.sub(lambda m: m.group(1) + value, text, count=1)
    if text and not text.endswith(("\n", "\r")):
        text += newline
    return text + f"{key}={value}{newline}"


def _remove_env_key(text: str, key: str) -> str:
    return re.sub(rf"^\s*{re.escape(key)}\s*=.*(\r?\n)?", "", text, flags=re.M)


def _parts(url: str):
    u = urlparse(url.replace("postgresql+psycopg2", "postgresql", 1))
    return dict(user=unquote(u.username or ""), password=unquote(u.password or ""),
                host=u.hostname or "localhost", port=u.port or 5432, dbname=u.path.lstrip("/"))


def _url(user: str, password: str, host: str, port: int, dbname: str) -> str:
    return f"postgresql+psycopg2://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}/{dbname}"


def _restrict_to_current_user(path: Path) -> None:
    """Best effort: owner-only permissions on the stored admin credential."""
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        if user:
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                           capture_output=True)
    else:
        os.chmod(path, 0o600)


# ---------------------------------------------------------------- admin login

def _load_admin_url(env_text: str):
    if os.environ.get(ADMIN_KEY):
        return os.environ[ADMIN_KEY], "environment"
    if ADMIN_FILE.exists():
        found = _read_env_value(ADMIN_FILE.read_text(encoding="utf-8"), ADMIN_KEY)
        if found:
            return found, str(ADMIN_FILE)
    current = _read_env_value(env_text, "DATABASE_URL")
    if current:
        return current, ".env (first run)"
    return None, None


def _connect(parts: dict, dbname: str | None = None, password: str | None = None):
    return psycopg2.connect(host=parts["host"], port=parts["port"], dbname=dbname or parts["dbname"],
                            user=parts["user"], password=password if password is not None else parts["password"],
                            connect_timeout=10)


# ----------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rotate", action="store_true", help="issue new passwords for existing roles")
    args = ap.parse_args()

    if not ENV_PATH.exists():
        print("ERROR: .env not found; copy .env.example to .env first.", file=sys.stderr)
        return 2
    env_text = ENV_PATH.read_text(encoding="utf-8")

    admin_url, source = _load_admin_url(env_text)
    if not admin_url:
        print(f"ERROR: no administrator credential. Set {ADMIN_KEY}.", file=sys.stderr)
        return 2
    admin = _parts(admin_url)
    dbname = admin["dbname"] or "qrscs"
    host, port = admin["host"], admin["port"]
    print(f"administrator credential source: {source}")

    conn = _connect(admin, dbname)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    if not cur.fetchone()[0]:
        print("ERROR: the administrator credential is not a superuser; nothing changed.", file=sys.stderr)
        return 2

    # The grants below name tables that only exist once the schema has been
    # migrated. Stop before changing anything (a role created here whose
    # password then never reached .env would be unusable) and say what to do.
    cur.execute("SELECT to_regclass('public.alembic_version') IS NOT NULL "
                "AND to_regclass('public.users') IS NOT NULL")
    if not cur.fetchone()[0]:
        print(f"ERROR: database {dbname!r} has no application schema yet; nothing changed.\n"
              "       Run `alembic upgrade head` first (with DATABASE_URL still set to the\n"
              "       administrator login), then run this script.", file=sys.stderr)
        return 2

    ident = sql.Identifier
    new_passwords: dict[str, str] = {}

    def ensure_role(name: str) -> None:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,))
        exists = cur.fetchone() is not None
        if not exists or args.rotate:
            password = secrets.token_urlsafe(32)
            verb = "ALTER" if exists else "CREATE"
            cur.execute(sql.SQL(
                f"{verb} ROLE {{}} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
                "NOBYPASSRLS INHERIT PASSWORD {}").format(ident(name), sql.Literal(password)))
            new_passwords[name] = password
            print(f"role {name}: {'rotated' if exists else 'created'}")
        else:
            # Re-assert the restrictions without touching the password.
            cur.execute(sql.SQL(
                "ALTER ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            ).format(ident(name)))
            print(f"role {name}: exists (password unchanged, restrictions re-applied)")

    ensure_role(MIGRATOR_ROLE)
    ensure_role(APP_ROLE)

    # Migrator owns the database and everything in it.
    cur.execute(sql.SQL("ALTER DATABASE {} OWNER TO {}").format(ident(dbname), ident(MIGRATOR_ROLE)))
    cur.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(ident(dbname)))
    cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(ident(dbname), ident(APP_ROLE)))
    cur.execute(sql.SQL("ALTER SCHEMA public OWNER TO {}").format(ident(MIGRATOR_ROLE)))
    cur.execute("SELECT format('%I.%I', schemaname, tablename) FROM pg_tables WHERE schemaname = 'public'")
    for (t,) in cur.fetchall():
        cur.execute(sql.SQL("ALTER TABLE {} OWNER TO {}").format(sql.SQL(t), ident(MIGRATOR_ROLE)))
    cur.execute("SELECT format('%I.%I', schemaname, sequencename) FROM pg_sequences WHERE schemaname = 'public'")
    for (q,) in cur.fetchall():
        cur.execute(sql.SQL("ALTER SEQUENCE {} OWNER TO {}").format(sql.SQL(q), ident(MIGRATOR_ROLE)))

    # Application role: DML only.
    cur.execute(sql.SQL("REVOKE ALL ON SCHEMA public FROM PUBLIC"))
    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(ident(APP_ROLE)))
    cur.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(ident(APP_ROLE)))
    cur.execute(sql.SQL(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(ident(APP_ROLE)))
    cur.execute(sql.SQL("REVOKE ALL ON TABLE public.alembic_version FROM {}").format(ident(APP_ROLE)))
    cur.execute(sql.SQL(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(ident(APP_ROLE)))
    cur.execute(sql.SQL(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(ident(MIGRATOR_ROLE), ident(APP_ROLE)))
    cur.execute(sql.SQL(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public "
        "GRANT USAGE, SELECT ON SEQUENCES TO {}").format(ident(MIGRATOR_ROLE), ident(APP_ROLE)))
    cur.close()
    conn.close()

    # Persist: administrator credential out of .env; role credentials in.
    if source == ".env (first run)":
        ADMIN_FILE.parent.mkdir(parents=True, exist_ok=True)
        ADMIN_FILE.write_text(f"{ADMIN_KEY}={admin_url}\n", encoding="utf-8")
        _restrict_to_current_user(ADMIN_FILE)
        print(f"administrator credential moved to {ADMIN_FILE} (outside the repository)")

    for role, key in ((APP_ROLE, "DATABASE_URL"), (MIGRATOR_ROLE, "MIGRATION_DATABASE_URL")):
        if role in new_passwords:
            env_text = _set_env_value(env_text, key, _url(role, new_passwords[role], host, port, dbname))
        elif _read_env_value(env_text, key) is None or _parts(_read_env_value(env_text, key) or "")["user"] != role:
            print(f"WARNING: {key} in .env does not use {role}; rerun with --rotate to issue a password.",
                  file=sys.stderr)
    ENV_PATH.write_text(env_text, encoding="utf-8", newline="")

    # Verify what was actually achieved, as the new roles.
    return 0 if _verify(env_text, dbname) else 1


def _verify(env_text: str, dbname: str) -> bool:
    ok = True

    def check(label: str, good: bool) -> None:
        nonlocal ok
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {label}")

    print("verification:")
    app = _parts(_read_env_value(env_text, "DATABASE_URL") or "")
    mig = _parts(_read_env_value(env_text, "MIGRATION_DATABASE_URL") or "")
    check("DATABASE_URL uses the runtime role", app["user"] == APP_ROLE)
    check("MIGRATION_DATABASE_URL uses the migration role", mig["user"] == MIGRATOR_ROLE)

    c = _connect(app, dbname); c.autocommit = True; cur = c.cursor()
    cur.execute("SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user")
    check("runtime role has no superuser/createdb/createrole/replication/bypassrls", not any(cur.fetchone()))
    cur.execute("SELECT count(*) FROM users")
    check("runtime role can read application tables", True)

    def denied(statement: str) -> bool:
        try:
            cur.execute(statement)
            return False
        except psycopg2.errors.InsufficientPrivilege:
            return True
        except psycopg2.Error:
            return True

    check("runtime role cannot CREATE TABLE", denied("CREATE TABLE qrscs_privilege_probe (x int)"))
    check("runtime role cannot DROP an application table", denied("DROP TABLE users"))
    check("runtime role cannot TRUNCATE", denied("TRUNCATE TABLE users"))
    check("runtime role cannot read alembic_version", denied("SELECT * FROM alembic_version"))
    check("runtime role cannot CREATE ROLE", denied("CREATE ROLE qrscs_probe_role"))
    check("runtime role cannot ALTER SYSTEM", denied("ALTER SYSTEM SET work_mem = '4MB'"))
    cur.close(); c.close()

    c = _connect(mig, dbname); c.autocommit = True; cur = c.cursor()
    cur.execute("SELECT version_num FROM alembic_version")
    check("migration role can read the Alembic revision", cur.fetchone() is not None)
    cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    check("migration role is not a superuser", not cur.fetchone()[0])
    cur.close(); c.close()
    return ok


if __name__ == "__main__":
    raise SystemExit(main())
