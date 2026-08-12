"""
Development TLS certificate generator.

Generates a throwaway development Certificate Authority and a server
certificate signed by it, for local development and test use only
(TLS Transport Security phase). Run manually, once, after cloning:

    python scripts/generate_dev_certs.py

Writes four files under certs/dev/ (gitignored -- see .gitignore and
docs/architecture/tls_transport.md):

    ca.crt      -- development CA certificate (public; the client
                   trusts this)
    ca.key      -- development CA private key (NEVER commit)
    server.crt  -- server certificate, signed by ca.key, with SAN
                   covering every entry in config.TLS_CERT_SANS
                   (default 127.0.0.1 and localhost). Set the
                   TLS_CERT_SANS environment variable to include a LAN
                   IP or DNS name for multi-device deployment, e.g.
                   TLS_CERT_SANS=192.168.1.42,127.0.0.1,localhost
    server.key  -- server private key (NEVER commit)

Safe to re-run: overwrites any existing files in certs/dev/ with a
fresh CA and server certificate -- e.g. after the development
certificate expires, or if the key material is ever suspected
compromised.

Validity is intentionally short for a development certificate (see
CA_VALIDITY_DAYS/SERVER_VALIDITY_DAYS below) rather than an
unnecessarily long-lived one -- long enough not to expire mid-project,
short enough that an expired certificate is quickly noticed and (since
this script is idempotent) trivially regenerated. Not representative
of production certificate lifecycle management, which is the issuing
CA's responsibility, not this script's.

generate_dev_ca()/generate_server_cert() are also imported directly by
tests/test_tls_transport.py to build throwaway certificates for its
negative-path tests (an untrusted CA, a certificate with the wrong
SAN) -- the same certificate-construction logic is used everywhere,
never duplicated.

Uses the `cryptography` package, already a project dependency -- no
new dependency is introduced for this.
"""

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import TLS_CERT_SANS

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs" / "dev"

CA_VALIDITY_DAYS = 730  # ~2 years
SERVER_VALIDITY_DAYS = 365  # ~1 year


def _generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def generate_dev_ca(common_name="QRSCP Development CA", validity_days=CA_VALIDITY_DAYS):
    """Generate a self-signed development CA key + certificate."""

    key = _generate_key()

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )

    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    return key, cert


def generate_server_cert(
    ca_key,
    ca_cert,
    common_name="127.0.0.1",
    sans=("127.0.0.1", "localhost"),
    validity_days=SERVER_VALIDITY_DAYS,
):
    """
    Generate a server key + certificate signed by the given CA.

    ``sans`` entries are classified automatically: anything that
    parses as an IP address becomes an IPAddress SAN entry, everything
    else becomes a DNSName entry -- so a caller can pass a mix (e.g.
    ["127.0.0.1", "localhost"]) without choosing the SAN type itself.
    """

    key = _generate_key()

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    san_entries = []

    for entry in sans:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_entries.append(x509.DNSName(entry))

    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    return key, cert


def main():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    # SANs come from config.TLS_CERT_SANS (D0 -- Configuration &
    # Network Separation) instead of this function's previously
    # hardcoded pair, so a LAN IP or DNS name can be included via
    # TLS_CERT_SANS without editing this script. The default
    # ("127.0.0.1,localhost") reproduces the previous behavior
    # exactly. generate_server_cert() itself is unchanged -- it has
    # always taken ``sans``; only what main() passes is now
    # configurable.
    sans = TLS_CERT_SANS

    ca_key, ca_cert = generate_dev_ca()
    _write_key(CERTS_DIR / "ca.key", ca_key)
    _write_cert(CERTS_DIR / "ca.crt", ca_cert)

    # The certificate's CN is cosmetic for verification purposes
    # (Python's ssl matches SAN entries only, never CN -- see
    # docs/architecture/tls_transport.md), but keeping it aligned with
    # the primary SAN makes the certificate self-describing in
    # openssl/browser output.
    server_key, server_cert = generate_server_cert(
        ca_key, ca_cert, common_name=sans[0], sans=sans
    )
    _write_key(CERTS_DIR / "server.key", server_key)
    _write_cert(CERTS_DIR / "server.crt", server_cert)

    print(f"Development CA and server certificate written to {CERTS_DIR}")
    print(
        f"  CA valid {CA_VALIDITY_DAYS} days, "
        f"server cert valid {SERVER_VALIDITY_DAYS} days"
    )
    print(f"  SAN: {', '.join(sans)}")
    print(
        "  Clients verify SERVER_HOST against these entries -- every "
        "address used to reach this server must be listed."
    )


if __name__ == "__main__":
    main()
