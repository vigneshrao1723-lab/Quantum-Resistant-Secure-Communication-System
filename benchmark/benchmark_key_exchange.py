"""
RSA-2048 vs Kyber (ML-KEM-768) key-exchange benchmark.

Measures the key-exchange implementations this project actually ships
-- crypto/rsa.py, crypto/kyber.py and the crypto/key_manager.py
orchestration on top of them. Nothing is reimplemented for
measurement: every timed call is a call the application itself makes.

What is measured
----------------
Two levels, because both are meaningful:

  primitive    RSAEncryption / KyberKEM directly -- the raw
               cryptographic operations.

  application  KeyManager, composed exactly as
               ClientSession.establish_session_key() and
               handle_session_key() compose it. RSA there is
               os.urandom(32) -> encrypt_session_key() -> base64;
               Kyber is encapsulate_session_key(), which derives the
               secret itself. Group-key wrapping
               (wrap_key_for_member / unwrap_received_key) is measured
               too, since it is a second real path and Kyber takes a
               KEM-then-DEM route there.

Sizes are recorded both raw and "on the wire" (PEM for RSA, base64 for
Kyber), because the wire form is what the protocol actually transmits.

READ THIS BEFORE COMPARING TIMES
--------------------------------
The two libraries are not implemented comparably:

  cryptography (RSA)  native -- compiled Rust/OpenSSL bindings
  kyber-py (ML-KEM)   pure Python

So a timing difference between them is dominated by implementation
language and optimisation level, NOT by the intrinsic cost of the
algorithms. A pure-Python RSA or a native ML-KEM would move these
numbers by orders of magnitude. Timing results here are therefore
valid as "what this application currently costs", and are NOT evidence
about which algorithm is inherently faster.

The SIZE measurements do not have that problem: key and ciphertext
sizes are fixed by the algorithm specifications (FIPS 203 for
ML-KEM-768, PKCS#1/OAEP for RSA-2048) and are identical in any
conforming implementation.

Reproducibility
---------------
Fixed iteration and warm-up counts (overridable), full environment
capture (Python, platform, CPU, library versions), and per-measurement
mean / stdev / median / min / max rather than a single sample. Timing
still varies between runs -- these are wall-clock measurements on a
multitasking OS, and the cryptographic operations consume real
entropy, so exact repetition is not achievable by design. Sizes are
exact and repeat exactly.

Usage
-----
    python -m benchmark.benchmark_key_exchange
    python -m benchmark.benchmark_key_exchange --iterations 500
    python -m benchmark.benchmark_key_exchange --output results.json

Does not read or modify config.KEY_EXCHANGE_ALGORITHM: the project
default is left exactly as it is. The KeyManager measurements set the
algorithm on the module attribute for the duration of the measurement
and restore it afterwards -- the same mechanism
tests/test_rsa_key_exchange_integration.py uses.
"""

import argparse
import base64
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import crypto.key_manager as key_manager_module
from crypto.key_manager import KeyManager
from crypto.kyber import KyberKEM
from crypto.rsa import RSAEncryption

DEFAULT_ITERATIONS = 200
DEFAULT_WARMUP = 20

# Key generation is far more expensive than the other operations, so it
# gets its own (smaller) count -- 200 RSA-2048 keygens would dominate
# the runtime without improving the estimate.
DEFAULT_KEYGEN_ITERATIONS = 25
DEFAULT_KEYGEN_WARMUP = 3


# ----------------------------------------------------------------------
# Measurement
# ----------------------------------------------------------------------

def measure(operation, iterations, warmup, setup=None):
    """
    Time ``operation`` ``iterations`` times and return summary
    statistics in milliseconds.

    ``setup``, when given, runs before each timed call and its result
    is passed to ``operation`` -- so per-iteration preparation (making
    a fresh key to decapsulate, say) stays outside the measurement.
    """

    for _ in range(warmup):
        operation(setup() if setup else None)

    samples = []

    for _ in range(iterations):
        argument = setup() if setup else None

        start = time.perf_counter()
        operation(argument)
        elapsed = time.perf_counter() - start

        samples.append(elapsed * 1000.0)

    return {
        "iterations": iterations,
        "mean_ms": statistics.fmean(samples),
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "median_ms": statistics.median(samples),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


# ----------------------------------------------------------------------
# Primitive level -- crypto/rsa.py and crypto/kyber.py directly
# ----------------------------------------------------------------------

def benchmark_rsa_primitives(iterations, warmup, keygen_iterations, keygen_warmup):
    results = {}

    def keygen(_):
        rsa = RSAEncryption()
        rsa.generate_keys()
        return rsa

    results["key_generation"] = measure(keygen, keygen_iterations, keygen_warmup)

    sender = RSAEncryption()
    sender.generate_keys()

    receiver = RSAEncryption()
    receiver.generate_keys()

    receiver_public_pem = receiver.export_public_key()
    receiver_public = RSAEncryption.import_public_key(receiver_public_pem)

    results["public_key_export"] = measure(
        lambda _: receiver.export_public_key(), iterations, warmup
    )
    results["public_key_import"] = measure(
        lambda _: RSAEncryption.import_public_key(receiver_public_pem),
        iterations,
        warmup,
    )

    # RSA is a PKE: the caller supplies the secret to protect.
    results["key_exchange"] = measure(
        lambda _: sender.encrypt(os.urandom(32), receiver_public), iterations, warmup
    )

    ciphertext = sender.encrypt(os.urandom(32), receiver_public)

    results["key_recovery"] = measure(
        lambda _: receiver.decrypt(ciphertext), iterations, warmup
    )

    results["sizes_bytes"] = {
        "public_key_raw": receiver.public_key.public_numbers().n.bit_length() // 8,
        "public_key_wire_pem": len(receiver_public_pem),
        "ciphertext_raw": len(ciphertext),
        "ciphertext_wire_base64": len(base64.b64encode(ciphertext)),
        "shared_secret": 32,
    }

    return results


def benchmark_kyber_primitives(iterations, warmup, keygen_iterations, keygen_warmup):
    results = {}

    def keygen(_):
        kyber = KyberKEM()
        kyber.generate_keys()
        return kyber

    results["key_generation"] = measure(keygen, keygen_iterations, keygen_warmup)

    sender = KyberKEM()
    sender.generate_keys()

    receiver = KyberKEM()
    receiver.generate_keys()

    receiver_public_b64 = receiver.export_public_key()
    receiver_public = KyberKEM.import_public_key(receiver_public_b64)

    results["public_key_export"] = measure(
        lambda _: receiver.export_public_key(), iterations, warmup
    )
    results["public_key_import"] = measure(
        lambda _: KyberKEM.import_public_key(receiver_public_b64), iterations, warmup
    )

    # Kyber is a KEM: encapsulation derives the secret itself.
    results["key_exchange"] = measure(
        lambda _: sender.encapsulate(receiver_public), iterations, warmup
    )

    ciphertext_b64, _secret = sender.encapsulate(receiver_public)

    results["key_recovery"] = measure(
        lambda _: receiver.decapsulate(ciphertext_b64), iterations, warmup
    )

    results["sizes_bytes"] = {
        "public_key_raw": len(receiver.encapsulation_key),
        "public_key_wire_base64": len(receiver_public_b64.encode("ascii")),
        "ciphertext_raw": len(base64.b64decode(ciphertext_b64)),
        "ciphertext_wire_base64": len(ciphertext_b64.encode("ascii")),
        "shared_secret": 32,
    }

    return results


# ----------------------------------------------------------------------
# Application level -- KeyManager, composed as ClientSession composes it
# ----------------------------------------------------------------------

def _key_managers_for(algorithm):
    """Two KeyManagers in ``algorithm`` mode that already know each
    other's public key -- the state two connected clients reach after
    distribute_public_keys()."""

    original = key_manager_module.KEY_EXCHANGE_ALGORITHM

    try:
        key_manager_module.KEY_EXCHANGE_ALGORITHM = algorithm

        sender = KeyManager()
        receiver = KeyManager()
    finally:
        key_manager_module.KEY_EXCHANGE_ALGORITHM = original

    sender.add_public_key("receiver", receiver.public_key)
    receiver.add_public_key("sender", sender.public_key)

    return sender, receiver


def benchmark_application_path(algorithm, iterations, warmup):
    """
    The session-key establishment ClientSession actually performs, and
    the group-key wrapping used for group conversations.
    """

    sender, receiver = _key_managers_for(algorithm)

    results = {"algorithm_in_use": sender.algorithm}

    if algorithm == "KYBER":

        def establish(_):
            return sender.encapsulate_session_key("receiver")

        ciphertext, _secret = sender.encapsulate_session_key("receiver")

        def recover(_):
            return receiver.decapsulate_session_key(ciphertext)

    else:

        def establish(_):
            session_key = os.urandom(32)
            wrapped = sender.encrypt_session_key("receiver", session_key)
            return base64.b64encode(wrapped).decode("utf-8")

        ciphertext = establish(None)

        def recover(_):
            return receiver.decrypt_session_key(base64.b64decode(ciphertext))

    results["session_key_establish"] = measure(establish, iterations, warmup)
    results["session_key_recover"] = measure(recover, iterations, warmup)

    results["session_key_total_round_trip"] = {
        "mean_ms": (
            results["session_key_establish"]["mean_ms"]
            + results["session_key_recover"]["mean_ms"]
        ),
        "note": "establish + recover; excludes key generation (once per login)",
    }

    # Group-key distribution: Kyber uses KEM-then-DEM here, RSA wraps
    # the caller-chosen key directly.
    group_key = os.urandom(32)

    results["group_key_wrap"] = measure(
        lambda _: sender.wrap_key_for_member("receiver", group_key),
        iterations,
        warmup,
    )

    encapsulation, wrapped_key = sender.wrap_key_for_member("receiver", group_key)

    results["group_key_unwrap"] = measure(
        lambda _: receiver.unwrap_received_key(encapsulation, wrapped_key),
        iterations,
        warmup,
    )

    results["sizes_bytes"] = {
        "session_key_ciphertext_wire": len(
            ciphertext.encode("ascii") if isinstance(ciphertext, str) else ciphertext
        ),
        "group_wrapped_key_wire": len(wrapped_key.encode("ascii")),
        "group_encapsulation_wire": (
            len(encapsulation.encode("ascii")) if encapsulation else 0
        ),
    }

    return results


# ----------------------------------------------------------------------
# Environment / reporting
# ----------------------------------------------------------------------

def collect_environment():
    def version_of(package):
        try:
            from importlib.metadata import version

            return version(package)
        except Exception:  # noqa: BLE001 - reporting only, never fatal
            return "unknown"

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
        "cryptography_version": version_of("cryptography"),
        "kyber_py_version": version_of("kyber-py"),
        "pycryptodome_version": version_of("pycryptodome"),
        "rsa_backend": "native (cryptography / Rust+OpenSSL bindings)",
        "kyber_backend": "pure Python (kyber-py)",
    }


def _row(label, stats):
    return (
        f"  {label:<28} {stats['mean_ms']:>10.3f} {stats['stdev_ms']:>10.3f} "
        f"{stats['median_ms']:>10.3f} {stats['min_ms']:>10.3f} {stats['max_ms']:>10.3f}"
    )


def print_report(results):
    env = results["environment"]

    print("=" * 78)
    print(" RSA-2048 vs Kyber (ML-KEM-768) key-exchange benchmark")
    print("=" * 78)
    print(f" {env['timestamp_utc']}")
    print(f" Python {env['python']} on {env['platform']}")
    print(f" cryptography {env['cryptography_version']} (native)  |  "
          f"kyber-py {env['kyber_py_version']} (pure Python)")
    print("=" * 78)

    header = (
        f"  {'operation':<28} {'mean ms':>10} {'stdev':>10} "
        f"{'median':>10} {'min':>10} {'max':>10}"
    )

    for level in ("primitive", "application"):
        for algorithm in ("RSA", "KYBER"):
            section = results[level][algorithm]

            print()
            print(f"[{level}] {algorithm}")
            print(header)

            for key, value in section.items():
                if isinstance(value, dict) and "mean_ms" in value and "stdev_ms" in value:
                    print(_row(key, value))

            if "session_key_total_round_trip" in section:
                total = section["session_key_total_round_trip"]
                print(f"  {'session_key_total_round_trip':<28} "
                      f"{total['mean_ms']:>10.3f}")

    print()
    print("[sizes] bytes")
    for level in ("primitive", "application"):
        for algorithm in ("RSA", "KYBER"):
            sizes = results[level][algorithm].get("sizes_bytes", {})
            if sizes:
                print(f"  {level}/{algorithm}:")
                for name, value in sizes.items():
                    print(f"    {name:<32} {value:>8}")

    print()
    print("-" * 78)
    print(" Timing compares IMPLEMENTATIONS, not algorithms: RSA here is native")
    print(" compiled code, ML-KEM is pure Python. Sizes are algorithm-intrinsic")
    print(" and hold for any conforming implementation.")
    print("-" * 78)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark this project's RSA-2048 and ML-KEM-768 key exchange."
    )
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument(
        "--keygen-iterations", type=int, default=DEFAULT_KEYGEN_ITERATIONS
    )
    parser.add_argument("--keygen-warmup", type=int, default=DEFAULT_KEYGEN_WARMUP)
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "key_exchange.json"),
        help="where to write the JSON results",
    )

    args = parser.parse_args()

    results = {
        "environment": collect_environment(),
        "configuration": {
            "iterations": args.iterations,
            "warmup": args.warmup,
            "keygen_iterations": args.keygen_iterations,
            "keygen_warmup": args.keygen_warmup,
        },
        "primitive": {
            "RSA": benchmark_rsa_primitives(
                args.iterations, args.warmup,
                args.keygen_iterations, args.keygen_warmup,
            ),
            "KYBER": benchmark_kyber_primitives(
                args.iterations, args.warmup,
                args.keygen_iterations, args.keygen_warmup,
            ),
        },
        "application": {
            "RSA": benchmark_application_path("RSA", args.iterations, args.warmup),
            "KYBER": benchmark_application_path("KYBER", args.iterations, args.warmup),
        },
        "interpretation": {
            "timing_caveat": (
                "RSA is measured through native compiled bindings "
                "(cryptography/Rust/OpenSSL); ML-KEM through a pure-Python "
                "library (kyber-py). Timing differences reflect implementation, "
                "not algorithm."
            ),
            "size_validity": (
                "Key and ciphertext sizes are fixed by FIPS 203 (ML-KEM-768) and "
                "RSA-2048/OAEP, so they hold for any conforming implementation."
            ),
        },
    }

    print_report(results)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"\nJSON results written to {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
