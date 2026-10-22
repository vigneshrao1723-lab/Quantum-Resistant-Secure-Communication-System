"""Summarise an acceptance run from the evidence it wrote (no credentials are ever in it).

    python scripts/acceptance_report.py [dist/acceptance/run-YYYYMMDD-HHMMSS]

Without an argument the newest run is used. Prints Markdown: account counts and per-scenario
results, exactly as recorded -- nothing is inferred.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    runs = sorted((ROOT / "dist" / "acceptance").glob("run-*"))
    target = Path(argv[1]) if len(argv) > 1 else (runs[-1] if runs else None)
    if target is None or not (target / "test_results.json").exists():
        print("no acceptance run with results found", file=sys.stderr)
        return 2

    results = json.loads((target / "test_results.json").read_text(encoding="utf-8"))
    accounts = json.loads((target / "accounts.json").read_text(encoding="utf-8")) if (target / "accounts.json").exists() else []

    print(f"# Acceptance run `{target.name}`\n")
    by_client = Counter(a["client"] for a in accounts)
    print(f"Population accounts attempted: {len(accounts)} "
          f"({', '.join(f'{n} {c}' for c, n in sorted(by_client.items())) or 'none'}); "
          f"registered {sum(a['registered'] for a in accounts)}, "
          f"logged in {sum(a['logged_in'] for a in accounts)}, "
          f"failed {sum(1 for a in accounts if a['error'])}.\n")

    counts = Counter(r["outcome"] for r in results)
    print(f"Scenarios: {len(results)} — " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) + "\n")
    print("| Scenario | Result | Seconds |\n|---|---|---|")
    for r in results:
        name = r["test"].split("::", 1)[-1]
        print(f"| `{name}` | {r['outcome']} | {r['seconds']} |")
    return 0 if set(counts) <= {"passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
