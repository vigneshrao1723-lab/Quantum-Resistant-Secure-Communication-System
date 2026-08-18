"""
Tests for D7 -- Remove remaining client -> database dependencies.

D2 through D4.3 removed every client-side database *call*: the client
makes no query, holds no session, and imports no repository. What
survived was a database *import*.

client/session.py needs three dataclasses from auth.schemas. Importing
a submodule runs its package's __init__ first, and auth/__init__.py
eagerly re-exported AuthenticationService / LoginService /
RegistrationService. Those reach database.repositories -> database ->
database.connection, which calls create_engine(DATABASE_URL) at module
scope and imports config_server. So a single dataclass import loaded
SQLAlchemy, psycopg2, a live PostgreSQL engine, and the server's
secret-bearing configuration -- JWT_SECRET_KEY included -- into every
client process.

Measured before the fix, with DATABASE_URL and JWT_SECRET_KEY unset:

    engine created at import: True
    engine URL the CLIENT built: postgresql+psycopg2://postgres:***@localhost:5432/qrscs
    config_server loaded in client process: True
    JWT_SECRET_KEY visible to client: 'ThisIsA_VeryStrongSecretKey_ForQuantumC...

This module asserts the boundary the way D0's
test_configuration_separation.py asserts its own: by importing in a
SUBPROCESS and inspecting sys.modules afterwards. That is a behavioural
check on the real import graph -- a source-text scan would miss a
dependency reached indirectly, which is exactly how this one arose.

DATABASE_URL and JWT_SECRET_KEY are cleared in every subprocess, so
these tests also prove the client needs no server configuration and no
PostgreSQL connectivity to start.

Run with:
    pytest tests/test_client_import_boundary.py -v
"""

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Every module a client process must never load. Named individually
# rather than pattern-matched, so allowing one back in has to be a
# deliberate edit here.
SERVER_ONLY_MODULE_PREFIXES = (
    "database",
    "sqlalchemy",
    "psycopg2",
    "config_server",
    "alembic",
)

# The client entry points. gui.main_window is the real application
# entry (main.py constructs MainWindow); client.session is the module
# that actually needs auth.schemas.
CLIENT_ENTRY_POINTS = ("client.session", "gui.main_window")


def _run_client_import(module_name, extra_body=""):
    """
    Import ``module_name`` in a clean subprocess with server
    configuration removed from the environment, and report which
    forbidden modules ended up in sys.modules.

    Returns (returncode, stdout, stderr).
    """

    code = (
        "import os, sys\n"
        # Prove the client needs neither of these to start.
        "os.environ.pop('DATABASE_URL', None)\n"
        "os.environ.pop('JWT_SECRET_KEY', None)\n"
        f"import {module_name}\n"
        f"forbidden = {SERVER_ONLY_MODULE_PREFIXES!r}\n"
        "loaded = sorted(\n"
        "    m for m in sys.modules\n"
        "    if any(m == f or m.startswith(f + '.') for f in forbidden)\n"
        ")\n"
        f"{extra_body}"
        "print('LOADED:' + ','.join(loaded))\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    return result.returncode, result.stdout, result.stderr


def _forbidden_modules_after_importing(module_name):
    returncode, stdout, stderr = _run_client_import(module_name)

    assert returncode == 0, (
        f"importing {module_name} failed in a clean environment:\n{stderr}"
    )

    line = next(
        (ln for ln in stdout.splitlines() if ln.startswith("LOADED:")), None
    )

    assert line is not None, f"probe produced no result. stdout={stdout!r}"

    payload = line[len("LOADED:"):].strip()

    return [m for m in payload.split(",") if m]


# ----------------------------------------------------------------------
# The boundary itself
# ----------------------------------------------------------------------

@pytest.mark.parametrize("module_name", CLIENT_ENTRY_POINTS)
def test_client_import_loads_no_server_only_module(module_name):
    """
    The core D7 assertion, for each client entry point: no database,
    SQLAlchemy, psycopg2, alembic, or config_server module may be
    present after the client is imported.
    """

    loaded = _forbidden_modules_after_importing(module_name)

    assert loaded == [], (
        f"importing {module_name} loaded server-only modules: {loaded}"
    )


@pytest.mark.parametrize("module_name", CLIENT_ENTRY_POINTS)
@pytest.mark.parametrize(
    "forbidden_prefix",
    ["database", "sqlalchemy", "psycopg2", "config_server"],
)
def test_client_import_avoids_each_server_dependency(
    module_name, forbidden_prefix
):
    """
    The same boundary stated one dependency at a time, so a failure
    names the specific thing that leaked back in rather than dumping a
    combined list.
    """

    loaded = _forbidden_modules_after_importing(module_name)
    offenders = [
        m
        for m in loaded
        if m == forbidden_prefix or m.startswith(forbidden_prefix + ".")
    ]

    assert offenders == [], (
        f"{module_name} loaded {forbidden_prefix}: {offenders}"
    )


def test_client_imports_without_database_url_or_jwt_secret():
    """
    D7 completion criterion stated directly: the client starts with no
    server configuration present. The subprocess clears both variables
    before importing, and additionally asserts no database engine
    object was constructed.
    """

    returncode, stdout, stderr = _run_client_import(
        "client.session",
        extra_body=(
            # Deliberately NOT asserted: that DATABASE_URL is still
            # absent from os.environ afterwards. config.py calls
            # load_dotenv() at import, so a developer checkout with a
            # local .env legitimately repopulates it. That is a
            # deployment-packaging question (what a shipped client's
            # .env contains), not an import-graph one, and asserting
            # it here would test dotenv rather than the D7 boundary.
            #
            # What actually proves the boundary is below: no database
            # engine module and no server configuration module were
            # loaded, and the client class is usable -- all with the
            # variables cleared before the import ran.
            "assert 'database.connection' not in sys.modules, (\n"
            "    'client built a database engine'\n"
            ")\n"
            "assert 'config_server' not in sys.modules, (\n"
            "    'client loaded server-only configuration'\n"
            ")\n"
            "from client.session import ClientSession\n"
            "assert ClientSession is not None\n"
            "print('CLIENT_OK')\n"
        ),
    )

    assert returncode == 0, f"client import failed:\n{stderr}"
    assert "CLIENT_OK" in stdout


def test_auth_schemas_alone_pulls_in_nothing_server_side():
    """
    The precise regression: auth.schemas is the one auth import the
    client makes, and it must stay free of the service classes'
    dependencies. This is the assertion that fails if a future change
    re-adds an eager service re-export to auth/__init__.py.
    """

    loaded = _forbidden_modules_after_importing("auth.schemas")

    assert loaded == [], (
        f"importing auth.schemas loaded server-only modules: {loaded}. "
        f"auth/__init__.py must not eagerly import the service classes."
    )


# ----------------------------------------------------------------------
# The server side must be unaffected
# ----------------------------------------------------------------------

def test_server_can_still_import_the_service_classes():
    """
    D7 changes only the import graph, never behaviour. Everything the
    package roots stopped re-exporting -- the auth services and the
    security handlers alike -- is still importable by its full module
    path, which is how every caller in this repository already imports
    them, and the server still reaches the database through them.
    """

    code = (
        "import sys\n"
        "from auth.authentication_service import AuthenticationService\n"
        "from auth.login_service import LoginService\n"
        "from auth.registration_service import RegistrationService\n"
        "from security.jwt_handler import JWTHandler\n"
        "from security.password_handler import PasswordHandler\n"
        "assert AuthenticationService and LoginService and RegistrationService\n"
        "assert JWTHandler and PasswordHandler\n"
        "assert 'database.connection' in sys.modules, (\n"
        "    'the server side must still reach the database'\n"
        ")\n"
        "assert 'config_server' in sys.modules, (\n"
        "    'the server side must still read its own configuration'\n"
        ")\n"
        "print('SERVER_OK')\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "SERVER_OK" in result.stdout


def test_auth_package_still_exports_the_schema_dataclasses():
    """
    The re-exports that D7 keeps. Nothing in the repository imports
    them this way today, but they are the documented package API and
    removing them would be an unrelated behavioural change.
    """

    import auth

    for name in (
        "AuthenticationResult",
        "LoginRequest",
        "RegisterRequest",
        "RegistrationResult",
        "TokenPair",
    ):
        assert hasattr(auth, name), f"auth.{name} is missing"
        assert name in auth.__all__


def test_auth_package_does_not_export_service_classes():
    """
    Locks in the mechanism, not just the symptom: the service classes
    must not be reachable as attributes of the package, because that
    is exactly what forced them to be imported eagerly.
    """

    import auth

    for name in ("AuthenticationService", "LoginService", "RegistrationService"):
        assert not hasattr(auth, name), (
            f"auth.{name} is re-exported again -- this restores the "
            f"client's dependency on the server database"
        )
        assert name not in auth.__all__


def test_security_package_does_not_export_handler_classes():
    """
    The same mechanism check for the second package D7 fixed.

    security/tls.py is client-safe, but jwt_handler and password_handler
    import config_server. Re-exporting either handler at the package
    root would make ``from security.tls import build_client_context``
    -- the one line the client needs -- pull the server's JWT signing
    secret back into the client process.
    """

    import security

    for name in ("JWTHandler", "PasswordHandler"):
        assert not hasattr(security, name), (
            f"security.{name} is re-exported again -- this restores the "
            f"client's dependency on the server's JWT signing secret"
        )

    assert getattr(security, "__all__", []) == [], (
        "security must not re-export anything at package level"
    )
