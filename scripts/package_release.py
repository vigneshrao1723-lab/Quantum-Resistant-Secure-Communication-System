"""
Build a source archive of the project that cannot carry local secrets.

    python scripts/package_release.py                 # -> dist/qrscs-source-YYYYMMDD.zip
    python scripts/package_release.py --output X.zip
    python scripts/package_release.py --verify X.zip  # validate an existing archive

What goes in: exactly the files Git would consider part of the project -- tracked
files plus untracked files that are not ignored (``git ls-files -co
--exclude-standard``) -- so everything in .gitignore (``.env``, ``certs/``,
``logs/``, ``storage_blobs/``, caches, virtualenvs...) stays out. A deny-list
then removes anything secret-shaped that is somehow not ignored.

What is then checked, on the finished archive (never on a list of names the
builder itself produced):
  1. no forbidden file names (env files other than .env.example, private keys,
     key stores, database dumps/files, token files, build output, caches);
  2. no private-key blocks, cloud keys, JWT-shaped tokens, or database URLs /
     secret assignments carrying a real-looking value (documented placeholders
     are allowed);
  3. none of this machine's own live secret values (the values in ``.env`` and in
     ~/.qrscs/admin.env) appear anywhere in any file.
A failed check deletes the archive and exits non-zero.

Findings are reported by file name and rule only -- a secret value is never
printed.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import os
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent

# Files that may never be archived, whatever Git thinks of them. Matched
# against the archive-relative POSIX path (and, for single-component patterns,
# the file name).
FORBIDDEN_NAME_PATTERNS = (
    ".env", ".env.*", "*.env",
    "*.key", "*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa*", "id_ed25519*",
    "*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.bak", "*.backup",
    "*token*.json", "*credentials*.json", "secrets.*",
    "*.apk", "*.aab", "*.log", "*.pyc", "*.pyo",
)
# Allowed even though they match a pattern above.
ALLOWED_NAMES = {".env.example", "ca.crt"}
FORBIDDEN_DIRS = {
    ".git", "certs", "logs", "storage_blobs", "__pycache__", ".pytest_cache", ".ruff_cache",
    ".buildozer", "bin", "venv", ".venv", "node_modules", ".keystore", "dist", ".claude",
}

# Text patterns. Each is (rule name, compiled regex, group holding the value or None).
_PLACEHOLDER = re.compile(
    r"^(REPLACE.*|<.*|\*+|x{3,}|pass(word)?|user|changeme|change-me|example|your[\w-]*|\.\.\.)(\\n)?$", re.I
)
# A value that is code reading the secret from somewhere else, not a secret
# (``JWT_SECRET_KEY = os.environ.get(...)``, ``SECRET_KEY=$SECRET_KEY``).
_CODE_REFERENCE = re.compile(r"^(os\.|environ|getenv|settings\.|config\.|\$|%|\{)|[()]")
SECRET_RULES = (
    ("private-key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), None),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("JWT-shaped token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), None),
    ("database URL with password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql)(?:\+\w+)?://[^\s:/@'\"]+:([^\s@'\"/]+)@"), 1),
    ("secret assignment",
     re.compile(r"""\b(?:JWT_SECRET_KEY|SECRET_KEY|DB_PASSWORD|POSTGRES_PASSWORD|API_KEY)\s*=(?!=)\s*['"]?([^\s'"#]+)"""), 1),
)
MAX_SCAN_BYTES = 5_000_000


@dataclass
class Finding:
    path: str
    rule: str

    def __str__(self) -> str:  # no values, ever
        return f"{self.path}: {self.rule}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings


# ---------------------------------------------------------------- live secrets

def _parse_env(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z_]\w*)\s*=\s*(.*?)\s*$", line)
        if m:
            out[m.group(1)] = m.group(2).strip("'\"")
    return out


def live_secret_values(root: Path | None = None) -> list[bytes]:
    """Secret values configured on THIS machine, for an exact-match leak check."""
    root = root or ROOT
    values: set[str] = set()
    sources = [root / ".env", Path.home() / ".qrscs" / "admin.env"]
    for src in sources:
        try:
            env = _parse_env(src.read_text(encoding="utf-8"))
        except OSError:
            continue
        for key, value in env.items():
            if key.endswith("DATABASE_URL"):
                try:
                    pw = unquote(urlparse(value.replace("+psycopg2", "", 1)).password or "")
                except ValueError:
                    pw = ""
                if len(pw) >= 8:
                    values.add(pw)
            elif re.search(r"SECRET|PASSWORD|TOKEN_KEY|PRIVATE", key, re.I) and len(value) >= 8:
                values.add(value)
    return [v.encode("utf-8") for v in sorted(values)]


# ------------------------------------------------------------------ validation

def _forbidden_name(rel: str) -> str | None:
    p = PurePosixPath(rel)
    if p.name in ALLOWED_NAMES:
        return None
    for part in p.parts[:-1]:
        if part in FORBIDDEN_DIRS:
            return f"forbidden directory '{part}/'"
    for pat in FORBIDDEN_NAME_PATTERNS:
        if fnmatch.fnmatch(p.name.lower(), pat.lower()):
            return f"forbidden file name pattern '{pat}'"
    return None


def scan_bytes(rel: str, data: bytes, live: list[bytes]) -> list[Finding]:
    findings: list[Finding] = []
    for value in live:
        if value in data:
            findings.append(Finding(rel, "contains a live secret value configured on this machine"))
            break
    if b"\x00" in data[:4096]:  # binary: only the exact-value check applies
        return findings
    text = data[:MAX_SCAN_BYTES].decode("utf-8", errors="ignore")
    for name, rx, group in SECRET_RULES:
        for m in rx.finditer(text):
            if group is not None and (
                _PLACEHOLDER.match(m.group(group)) or _CODE_REFERENCE.search(m.group(group))
            ):
                continue
            findings.append(Finding(rel, name))
            break
    return findings


def validate_archive(path: Path, live: list[bytes] | None = None) -> Report:
    live = live_secret_values() if live is None else live
    report = Report()
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            report.files += 1
            rel = info.filename
            reason = _forbidden_name(rel)
            if reason:
                report.findings.append(Finding(rel, reason))
                continue
            report.findings.extend(scan_bytes(rel, zf.read(info), live))
    return report


# ---------------------------------------------------------------------- build

def candidate_files(root: Path | None = None) -> list[str]:
    root = root or ROOT
    out = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=root, capture_output=True, check=True,
    ).stdout.decode("utf-8")
    return sorted({p for p in out.split("\0") if p})


def build_archive(output: Path, root: Path | None = None) -> Path:
    root = root or ROOT
    output.parent.mkdir(parents=True, exist_ok=True)
    included = 0
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in candidate_files(root):
            src = root / rel
            if not src.is_file() or _forbidden_name(rel):
                continue
            # Fixed timestamp keeps the archive reproducible for identical content.
            info = zipfile.ZipInfo(rel, date_time=(2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, src.read_bytes())
            included += 1
    return output


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--verify", type=Path, default=None, help="only validate an existing archive")
    args = ap.parse_args(argv)

    if args.verify:
        target = args.verify
    else:
        stamp = datetime.date.today().strftime("%Y%m%d")
        target = args.output or ROOT / "dist" / f"qrscs-source-{stamp}.zip"
        build_archive(target)

    report = validate_archive(target)
    if not report.ok:
        for f in report.findings:
            print(f"FORBIDDEN  {f}", file=sys.stderr)
        if not args.verify:
            target.unlink(missing_ok=True)
            print(f"archive deleted ({len(report.findings)} problem(s))", file=sys.stderr)
        return 1
    print(f"OK  {target}  ({report.files} files; no forbidden names, secret patterns or live secret values)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
