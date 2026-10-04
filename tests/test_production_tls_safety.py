"""
Phase 19.19 -- L-3 closure: production deployments must hard-fail
rather than silently start on this repository's own development TLS
material.

config.py::validate_config() already existed (D8/P1) and already
refuses APP_ENV=production when TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE
point at a path inside certs/dev/ -- but had ZERO test coverage before
this phase, and only caught the PATH staying at its default; a copy of
the same dev key bytes at a different path/filename sailed through.
Phase 19.19 closed that second gap with a content-hash comparison
(config.py, right after the existing path check) and this file proves
both checks, plus that development mode and a genuinely different
production certificate are both completely unaffected.

Runs config.py in an isolated subprocess per case (not an in-process
import/reload) -- validate_config() runs unconditionally at module
import time, and many other already-imported test modules hold
references to config's module-level constants; reloading it in-process
would leave the rest of this pytest session's config state inconsistent
depending on test order. A fresh subprocess is the only way to observe
"does this process refuse to start" in complete isolation.

Run with:
    pytest tests/test_production_tls_safety.py -v
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.generate_dev_certs import generate_dev_ca, generate_server_cert

ROOT_DIR = Path(__file__).resolve().parent.parent


def _run_config_import(extra_env):
    env = dict(os.environ)
    env.update(extra_env)
    # This project's own dev material is real, valid TLS_CERT_SANS
    # config either way -- not relevant to what's under test here.
    env.setdefault("TLS_CERT_SANS", "127.0.0.1,localhost")

    result = subprocess.run(
        [sys.executable, "-c", "import config"],
        cwd=str(ROOT_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


def test_development_mode_starts_on_the_projects_own_dev_certificate():
    result = _run_config_import({"APP_ENV": "development"})
    assert result.returncode == 0, result.stderr


def test_production_mode_rejects_default_dev_certificate_paths():
    """The pre-existing (D8/P1) path-based check: APP_ENV=production
    with TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE left at their defaults
    (which point straight at certs/dev/) must refuse to start."""

    result = _run_config_import({"APP_ENV": "production"})
    assert result.returncode != 0
    assert "development TLS material" in result.stderr


def test_production_mode_rejects_dev_certificate_content_at_a_different_path(tmp_path):
    """Phase 19.19's new check: the SAME dev key bytes, copied to a
    path that is NOT inside certs/dev/ and given a different filename
    -- the pre-existing path check alone would miss this."""

    copied_key = tmp_path / "totally_different_name.pem"
    copied_key.write_bytes((ROOT_DIR / "certs" / "dev" / "server.key").read_bytes())
    copied_cert = tmp_path / "not_obviously_dev_either.pem"
    copied_cert.write_bytes((ROOT_DIR / "certs" / "dev" / "server.crt").read_bytes())
    copied_ca = tmp_path / "ca_copy.pem"
    copied_ca.write_bytes((ROOT_DIR / "certs" / "dev" / "ca.crt").read_bytes())

    result = _run_config_import({
        "APP_ENV": "production",
        "TLS_CERT_FILE": str(copied_cert),
        "TLS_KEY_FILE": str(copied_key),
        "TLS_CA_FILE": str(copied_ca),
    })

    assert result.returncode != 0
    assert "byte-identical" in result.stderr


def test_production_mode_accepts_a_genuinely_different_certificate(tmp_path):
    """The checks above must not false-positive on real, independently
    generated production material -- proven with an actual, different
    self-signed CA + server certificate (same generator this project's
    own dev certs use, called a second time -- a fresh RSA keypair and
    random serial each call, never the same bytes)."""

    ca_key, ca_cert = generate_dev_ca(common_name="Not The Dev CA")
    server_key, server_cert = generate_server_cert(
        ca_key, ca_cert, common_name="prod.example.com", sans=["prod.example.com"]
    )

    from cryptography.hazmat.primitives import serialization

    key_path = tmp_path / "prod_server.key"
    key_path.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path = tmp_path / "prod_server.crt"
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    ca_path = tmp_path / "prod_ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    result = _run_config_import({
        "APP_ENV": "production",
        "TLS_CERT_FILE": str(cert_path),
        "TLS_KEY_FILE": str(key_path),
        "TLS_CA_FILE": str(ca_path),
        "TLS_CERT_SANS": "prod.example.com",
    })

    assert result.returncode == 0, result.stderr
