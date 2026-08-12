"""
Tests for D0 -- Configuration & Network Separation.

Two things are locked in here:

  1. The client/server configuration boundary. config.py is the
     shared, secret-free module a client deployment may hold;
     config_server.py holds the database URL, JWT signing secret,
     password-hashing parameters and blob-storage root, which a client
     must never need. These tests assert the boundary structurally, so
     a future change that quietly moves a secret back into the shared
     module fails here rather than shipping.

  2. The three-way network split (SERVER_BIND_HOST / SERVER_HOST /
     SERVER_PORT) that replaced the single hardcoded HOST, including
     that every default still reproduces the previous single-machine
     behavior exactly.

Scope limit these tests deliberately do NOT assert (see config.py's
own module docstring): client code still reaches the database
directly, so a client process today still imports config_server
transitively via database.connection. That dependency is removed by
the later phases which move those database operations behind the
server; D0 only establishes the boundary they will respect.

Run with:
    pytest tests/test_configuration_separation.py -v
"""

import ast
import importlib
import ipaddress
import subprocess
import sys
from pathlib import Path

import pytest

import config
import config_server

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Everything a client must never need. Named individually rather than
# discovered, so adding a new secret to config.py is a deliberate act
# that has to change this list too.
SERVER_ONLY_SETTINGS = (
    "DATABASE_URL",
    "JWT_SECRET_KEY",
    "JWT_ALGORITHM",
    "JWT_ISSUER",
    "JWT_AUDIENCE",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "REFRESH_TOKEN_EXPIRE_DAYS",
    "ARGON2_TIME_COST",
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "MAX_FAILED_LOGIN_ATTEMPTS",
    "FILE_STORAGE_ROOT",
)


# ----------------------------------------------------------------------
# The configuration boundary
# ----------------------------------------------------------------------


@pytest.mark.parametrize("setting", SERVER_ONLY_SETTINGS)
def test_shared_config_does_not_expose_server_only_setting(setting):
    assert not hasattr(config, setting), (
        f"config.{setting} is server-only and must live in config_server.py "
        f"-- config.py is shared with every client deployment."
    )


@pytest.mark.parametrize("setting", SERVER_ONLY_SETTINGS)
def test_server_config_exposes_server_only_setting(setting):
    assert hasattr(config_server, setting)


def test_shared_config_exposes_the_network_and_tls_settings():
    for setting in (
        "SERVER_HOST",
        "SERVER_BIND_HOST",
        "SERVER_PORT",
        "TLS_CERT_FILE",
        "TLS_KEY_FILE",
        "TLS_CA_FILE",
        "TLS_CERT_SANS",
    ):
        assert hasattr(config, setting), f"config.{setting} is missing"


def test_ambiguous_host_and_port_names_are_gone():
    """The single HOST/PORT pair previously served as both the
    server's bind interface and the client's connect target, which is
    exactly what made multi-device deployment inexpressible. A missed
    importer must fail loudly at import rather than silently dialling
    the wrong address, so the old names must not linger as aliases."""
    assert not hasattr(config, "HOST")
    assert not hasattr(config, "PORT")


def test_server_config_does_not_duplicate_shared_network_settings():
    """One definition per setting -- a second copy in config_server
    could silently disagree with the shared one."""
    for setting in ("SERVER_HOST", "SERVER_BIND_HOST", "SERVER_PORT"):
        assert not hasattr(config_server, setting)


# ----------------------------------------------------------------------
# Defaults preserve the previous single-machine behavior
# ----------------------------------------------------------------------


def test_defaults_preserve_localhost_behavior():
    assert config.SERVER_HOST == "127.0.0.1"
    assert config.SERVER_BIND_HOST == "127.0.0.1"
    assert config.SERVER_PORT == 5000


def test_bind_host_defaults_to_loopback_not_all_interfaces():
    """Exposure to other devices must be an explicit opt-in
    (SERVER_BIND_HOST=0.0.0.0), never the default -- a development
    server should not become LAN-reachable just by being started."""
    assert config.SERVER_BIND_HOST not in ("0.0.0.0", "::")


def test_default_tls_sans_match_the_default_server_host():
    """The client verifies SERVER_HOST against the certificate's SAN,
    so the shipped defaults must be mutually consistent or the
    out-of-the-box handshake fails."""
    assert config.SERVER_HOST in config.TLS_CERT_SANS
    assert "localhost" in config.TLS_CERT_SANS


def test_server_port_is_an_int_not_a_string():
    """socket.connect()/bind() require an int; an unconverted
    environment string would fail only at connection time."""
    assert isinstance(config.SERVER_PORT, int)


# ----------------------------------------------------------------------
# Environment overrides
# ----------------------------------------------------------------------


def _reload_config_with(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    # load_dotenv() does not overwrite variables already present in the
    # environment, so monkeypatch.setenv wins over .env here.
    return importlib.reload(config)


@pytest.fixture(autouse=True)
def _restore_config():
    """Any test that reloads config must leave the module as it found
    it -- other modules hold references to these values."""
    yield
    importlib.reload(config)


def test_server_host_is_overridable_for_a_lan_deployment(monkeypatch):
    reloaded = _reload_config_with(monkeypatch, SERVER_HOST="192.168.1.42")

    assert reloaded.SERVER_HOST == "192.168.1.42"
    # The bind interface is a separate setting and must not move with it.
    assert reloaded.SERVER_BIND_HOST == "127.0.0.1"


def test_bind_host_is_overridable_independently(monkeypatch):
    reloaded = _reload_config_with(monkeypatch, SERVER_BIND_HOST="0.0.0.0")

    assert reloaded.SERVER_BIND_HOST == "0.0.0.0"
    assert reloaded.SERVER_HOST == "127.0.0.1"


def test_server_port_is_overridable_and_parsed_as_int(monkeypatch):
    reloaded = _reload_config_with(monkeypatch, SERVER_PORT="6001")

    assert reloaded.SERVER_PORT == 6001
    assert isinstance(reloaded.SERVER_PORT, int)


def test_tls_cert_sans_parses_a_multi_entry_list(monkeypatch):
    reloaded = _reload_config_with(
        monkeypatch, TLS_CERT_SANS="192.168.1.42,127.0.0.1,localhost"
    )

    assert reloaded.TLS_CERT_SANS == ("192.168.1.42", "127.0.0.1", "localhost")


def test_tls_cert_sans_tolerates_whitespace_and_trailing_commas(monkeypatch):
    reloaded = _reload_config_with(
        monkeypatch, TLS_CERT_SANS=" 192.168.1.42 , localhost , "
    )

    assert reloaded.TLS_CERT_SANS == ("192.168.1.42", "localhost")


def test_invalid_server_port_is_rejected_at_import(monkeypatch):
    monkeypatch.setenv("SERVER_PORT", "70000")

    with pytest.raises(ValueError, match="SERVER_PORT"):
        importlib.reload(config)


def test_empty_tls_cert_sans_is_rejected_at_import(monkeypatch):
    monkeypatch.setenv("TLS_CERT_SANS", "  ,  ")

    with pytest.raises(ValueError, match="TLS_CERT_SANS"):
        importlib.reload(config)


# ----------------------------------------------------------------------
# The settings are actually wired into the client and the server
# ----------------------------------------------------------------------


def _imported_config_names(module_path):
    """Names a module actually imports from config -- parsed rather
    than text-matched, so prose in a comment or docstring can mention
    a setting without counting as a use of it."""
    tree = ast.parse(Path(module_path).read_text(encoding="utf-8"))

    names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("config", "config_server"):
            names.update(alias.name for alias in node.names)

    return names


def test_server_binds_the_bind_host_and_never_the_client_host():
    server_py = PROJECT_ROOT / "server" / "server.py"

    imported = _imported_config_names(server_py)

    assert "SERVER_BIND_HOST" in imported
    assert "SERVER_PORT" in imported
    # The server has no business dialling the client's target address.
    assert "SERVER_HOST" not in imported

    source = server_py.read_text(encoding="utf-8")
    assert "server_socket.bind((SERVER_BIND_HOST, SERVER_PORT))" in source


def test_client_dials_the_server_host_and_never_the_bind_host():
    import client.session as client_session

    assert client_session.SERVER_HOST == config.SERVER_HOST
    assert client_session.SERVER_PORT == config.SERVER_PORT
    assert not hasattr(client_session, "SERVER_BIND_HOST")


def test_client_modules_import_no_server_only_configuration():
    """The client may read the shared module; it must never import a
    setting out of config_server. (It still reaches config_server
    transitively via database.connection until the database
    operations move behind the server -- this asserts the direct
    import boundary, which is what D0 establishes.)"""
    for relative in (
        Path("client") / "session.py",
        Path("client") / "conversation_store.py",
        Path("client") / "client.py",
        Path("gui") / "main_window.py",
    ):
        module_path = PROJECT_ROOT / relative
        tree = ast.parse(module_path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != "config_server", (
                    f"{relative} imports from config_server -- server-only "
                    f"configuration must not be read by client code."
                )


def test_client_verifies_tls_against_the_address_it_dialled():
    """server_hostname must be the same value passed to connect(), or
    certificate verification checks an address nobody dialled."""
    source = (PROJECT_ROOT / "client" / "session.py").read_text(encoding="utf-8")

    assert "raw_socket.connect((SERVER_HOST, SERVER_PORT))" in source
    assert "server_hostname=SERVER_HOST" in source


def test_cert_generator_uses_configured_sans():
    source = (PROJECT_ROOT / "scripts" / "generate_dev_certs.py").read_text(
        encoding="utf-8"
    )

    assert "TLS_CERT_SANS" in source
    assert "sans=sans" in source


def test_every_configured_san_is_a_valid_ip_or_hostname():
    """generate_server_cert() classifies each entry as an IPAddress or
    DNSName SAN; a malformed entry would silently become a DNS name
    that can never match."""
    for entry in config.TLS_CERT_SANS:
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            assert entry and " " not in entry, f"invalid SAN entry: {entry!r}"


# ----------------------------------------------------------------------
# The shared module stands alone
# ----------------------------------------------------------------------


def test_shared_config_imports_without_any_server_credentials():
    """config.py must be importable by a client that holds no database
    URL and no JWT secret. Run in a subprocess with those variables
    cleared, since they are already set in this process (and .env is
    loaded by config itself, so the subprocess also points at a
    throwaway directory-free env)."""
    code = (
        "import os\n"
        "os.environ.pop('DATABASE_URL', None)\n"
        "os.environ.pop('JWT_SECRET_KEY', None)\n"
        "import config\n"
        "assert config.SERVER_PORT == 5000\n"
        "assert not hasattr(config, 'DATABASE_URL')\n"
        "assert not hasattr(config, 'JWT_SECRET_KEY')\n"
        "print('ok')\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_server_config_does_not_import_client_modules():
    """config_server must stay a leaf of the shared module only --
    importing client code from it would recreate the coupling this
    split removes."""
    source = (PROJECT_ROOT / "config_server.py").read_text(encoding="utf-8")

    assert "import client" not in source
    assert "import gui" not in source
    assert "from client" not in source
    assert "from gui" not in source
