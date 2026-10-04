"""
ML-DSA-65 (FIPS 204) benchmark.

Measures this project's actual ML-DSA implementation --
crypto/ml_dsa.py::MLDSASigner -- the same class client/session.py and
crypto/key_manager.py use to sign/verify every group-key distribution,
RSA session-key, message, and identity-announcement packet (see
crypto/identity_protocol.py, crypto/message_protocol.py,
crypto/group_key_protocol.py, crypto/session_key_protocol.py). Nothing
is reimplemented or mocked for measurement: every timed call is a call
MLDSASigner itself makes, backed by `cryptography`'s own audited
ML-DSA-65 implementation. Mirrors benchmark_key_exchange.py's own
methodology and reporting shape so both benchmarks in this directory
read the same way.

What is measured
-----------------
  key_generation   MLDSASigner.generate_keys()
  signing          MLDSASigner.sign() over a fixed-size representative
                    message.
  verification     MLDSASigner.verify() of a signature already known
                    to be valid.

MESSAGE_SIZE_BYTES (256) is representative of this project's real
signed payloads -- crypto/group_key_protocol.py, crypto/
session_key_protocol.py, crypto/message_protocol.py, crypto/
identity_protocol.py all produce small, length-prefixed canonical
encodings well under 1 KB. ML-DSA-65 signing/verification cost is
dominated by fixed lattice operations, not message length, so this
size is representative without needing to replicate every packet
shape exactly.

Correctness, not just speed
----------------------------
Every timed sample is verified for correctness immediately after being
timed (outside the timed window, so verification cost never pollutes
the measurement): each key-generation sample is checked against
ML-DSA-65's fixed key sizes; each signing sample is checked against
the fixed signature size AND independently re-verified with
MLDSASigner.verify() before being accepted; each verification sample
is checked to actually return True. A single correctness failure
aborts the whole benchmark run with a clear error instead of silently
reporting numbers next to a broken primitive -- see
measure_and_verify() below.

READ THIS BEFORE COMPARING TIMES
---------------------------------
Wall-clock timings below are environment-dependent performance data --
this specific machine, OS scheduler, Python interpreter, and
`cryptography` build -- not a portable, machine-independent property
of ML-DSA-65 itself. Re-running this benchmark on different hardware
will produce different numbers; the methodology (warm-up, iteration
count, mean/median/min/max/stdev) is fixed and deterministic, but the
timings themselves are not expected to reproduce identically. Sizes
(public key / private key seed / signature, all fixed by FIPS 204) ARE
exact and reproduce identically anywhere.

Usage
-----
    python -m benchmark.benchmark_ml_dsa
    python -m benchmark.benchmark_ml_dsa --iterations 500
    python -m benchmark.benchmark_ml_dsa --output results.json

Does not modify crypto/ml_dsa.py in any way.
"""

import argparse
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

from crypto.ml_dsa import (
    MLDSASigner,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_PRIVATE_SEED_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
)

DEFAULT_ITERATIONS = 200
DEFAULT_WARMUP = 20

# Key generation is the most expensive of the three operations here --
# same reasoning as benchmark_key_exchange.py's own
# DEFAULT_KEYGEN_ITERATIONS: a smaller, separate count keeps the run
# fast without weakening the estimate.
DEFAULT_KEYGEN_ITERATIONS = 100
DEFAULT_KEYGEN_WARMUP = 10

MESSAGE_SIZE_BYTES = 256


# ----------------------------------------------------------------------
# Measurement (+ correctness gate)
# ----------------------------------------------------------------------

def measure_and_verify(operation, verify, iterations, warmup, setup=None):
    """
    Time ``operation`` ``iterations`` times (after ``warmup`` untimed
    iterations) and return the same summary-statistics shape
    benchmark_key_exchange.py::measure() does, in milliseconds.

    ``verify(argument, result)`` runs immediately after each timed
    call, OUTSIDE the timed window, and must return True -- a single
    False (or a raised exception propagating out of ``operation``/
    ``verify`` themselves) aborts the benchmark immediately with a
    RuntimeError, rather than silently reporting timing numbers for an
    operation that did not actually behave correctly.
    """

    for _ in range(warmup):
        argument = setup() if setup else None
        result = operation(argument)
        if not verify(argument, result):
            raise RuntimeError(
                "ML-DSA correctness check failed during warm-up -- "
                "aborting before collecting any timed samples."
            )

    samples = []

    for i in range(iterations):
        argument = setup() if setup else None

        start = time.perf_counter()
        result = operation(argument)
        elapsed = time.perf_counter() - start

        if not verify(argument, result):
            raise RuntimeError(
                f"ML-DSA correctness check failed on iteration {i} -- "
                "aborting; refusing to report benchmark numbers for a "
                "primitive that just produced an incorrect result."
            )

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
# Operations
# ----------------------------------------------------------------------

def benchmark_key_generation(iterations, warmup):
    def keygen(_):
        signer = MLDSASigner()
        signer.generate_keys()
        return signer

    def verify(_argument, signer):
        public_key = signer.export_public_key()
        private_key = signer.export_private_key()
        return (
            len(public_key) == ML_DSA_65_PUBLIC_KEY_BYTES
            and len(private_key) == ML_DSA_65_PRIVATE_SEED_BYTES
        )

    return measure_and_verify(keygen, verify, iterations, warmup)


def benchmark_signing(iterations, warmup):
    signer = MLDSASigner()
    signer.generate_keys()
    public_key = signer.export_public_key()

    def setup():
        return os.urandom(MESSAGE_SIZE_BYTES)

    def sign(message):
        return signer.sign(message)

    def verify(message, signature):
        return (
            len(signature) == ML_DSA_65_SIGNATURE_BYTES
            and MLDSASigner.verify(message, signature, public_key)
        )

    return measure_and_verify(sign, verify, iterations, warmup, setup=setup)


def benchmark_verification(iterations, warmup):
    signer = MLDSASigner()
    signer.generate_keys()
    public_key = signer.export_public_key()

    def setup():
        message = os.urandom(MESSAGE_SIZE_BYTES)
        signature = signer.sign(message)
        return message, signature

    def do_verify(argument):
        message, signature = argument
        return MLDSASigner.verify(message, signature, public_key)

    def check(_argument, result):
        return result is True

    return measure_and_verify(do_verify, check, iterations, warmup, setup=setup)


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
        "backend": (
            "native (cryptography / Rust+OpenSSL bindings, "
            "cryptography.hazmat.primitives.asymmetric.mldsa)"
        ),
    }


def _row(label, stats):
    return (
        f"  {label:<20} {stats['mean_ms']:>10.4f} {stats['stdev_ms']:>10.4f} "
        f"{stats['median_ms']:>10.4f} {stats['min_ms']:>10.4f} {stats['max_ms']:>10.4f}"
    )


def print_report(results):
    env = results["environment"]

    print("=" * 78)
    print(" ML-DSA-65 (FIPS 204) benchmark")
    print("=" * 78)
    print(f" {env['timestamp_utc']}")
    print(f" Python {env['python']} on {env['platform']}")
    print(f" cryptography {env['cryptography_version']} (native)")
    print("=" * 78)
    print()

    header = (
        f"  {'operation':<20} {'mean ms':>10} {'stdev':>10} "
        f"{'median':>10} {'min':>10} {'max':>10}"
    )
    print(header)

    for key in ("key_generation", "signing", "verification"):
        print(_row(key, results["timing"][key]))

    print()
    print("[sizes] bytes (fixed by FIPS 204 -- ML-DSA-65)")
    for name, value in results["sizes_bytes"].items():
        print(f"    {name:<24} {value:>8}")

    print()
    print("-" * 78)
    print(" Every timed sample above was independently verified correct")
    print(" (key sizes, signature size, and signature validity) before being")
    print(" accepted -- see this script's own module docstring.")
    print(" Timings are environment-dependent performance data for THIS")
    print(" machine/run, not a portable property of the algorithm.")
    print("-" * 78)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark this project's ML-DSA-65 (crypto/ml_dsa.py) implementation."
    )
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument(
        "--keygen-iterations", type=int, default=DEFAULT_KEYGEN_ITERATIONS
    )
    parser.add_argument("--keygen-warmup", type=int, default=DEFAULT_KEYGEN_WARMUP)
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "benchmark" / "results" / "ml_dsa.json"),
        help="where to write the JSON results",
    )

    args = parser.parse_args()

    print(
        "Running ML-DSA-65 key generation benchmark "
        f"({args.keygen_iterations} iterations)..."
    )
    key_generation = benchmark_key_generation(
        args.keygen_iterations, args.keygen_warmup
    )

    print(f"Running ML-DSA-65 signing benchmark ({args.iterations} iterations)...")
    signing = benchmark_signing(args.iterations, args.warmup)

    print(
        f"Running ML-DSA-65 verification benchmark ({args.iterations} iterations)..."
    )
    verification = benchmark_verification(args.iterations, args.warmup)

    signer = MLDSASigner()
    signer.generate_keys()
    sample_signature = signer.sign(b"x" * MESSAGE_SIZE_BYTES)

    results = {
        "environment": collect_environment(),
        "configuration": {
            "iterations": args.iterations,
            "warmup": args.warmup,
            "keygen_iterations": args.keygen_iterations,
            "keygen_warmup": args.keygen_warmup,
            "message_size_bytes": MESSAGE_SIZE_BYTES,
        },
        "timing": {
            "key_generation": key_generation,
            "signing": signing,
            "verification": verification,
        },
        "sizes_bytes": {
            "public_key": len(signer.export_public_key()),
            "private_key_seed": len(signer.export_private_key()),
            "signature": len(sample_signature),
        },
        "correctness": {
            "every_sample_independently_verified": True,
            "note": (
                "Each timed key-generation sample was checked against the "
                "fixed ML-DSA-65 key sizes; each timed signing sample was "
                "checked against the fixed signature size AND independently "
                "re-verified with MLDSASigner.verify(); each timed "
                "verification sample was checked to actually return True. "
                "Any failure would have aborted this run before reaching "
                "this report."
            ),
        },
        "interpretation": {
            "timing_caveat": (
                "Timings are environment-dependent performance data for this "
                "machine/run (CPU, OS scheduler, Python interpreter, "
                "cryptography library build) -- not a portable, "
                "machine-independent property of ML-DSA-65."
            ),
            "size_validity": (
                "Key and signature sizes are fixed by FIPS 204 (ML-DSA-65) "
                "and hold for any conforming implementation."
            ),
        },
    }

    print()
    print_report(results)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"\nJSON results written to {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
