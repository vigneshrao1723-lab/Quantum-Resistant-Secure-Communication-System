"""
Release packaging: the source archive must never carry local secrets.

Drives scripts/package_release.py for real -- builds an archive of this
repository, builds archives of throwaway git repositories that are deliberately
misconfigured (no .gitignore), and feeds the validator hostile archives. No
secret value is ever asserted on or printed; only file names and rule names.
"""

import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts import package_release as pkg

REPO = Path(pkg.ROOT)
FAKE_SECRET = "Zq7-fake-secret-value-for-tests-only-0123456789"

# Hostile fixtures are assembled at runtime so that no secret-shaped literal
# exists in this file -- the packaging validator scans the repository's own
# sources, and must stay strict about them.
_BEGIN = "-----" + "BEGIN "
_END = "-----" + "END "
PRIVATE_KEY_BLOCK = _BEGIN + "PRIVATE " + "KEY-----\nAAAA\n" + _END + "PRIVATE " + "KEY-----\n"
RSA_KEY_START = _BEGIN + "RSA PRIVATE " + "KEY-----\nMIIE\n"
CERTIFICATE = _BEGIN + "CERTIFICATE-----\nAAAA\n" + _END + "CERTIFICATE-----\n"
JWT_LIKE = "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0." + "abcdefghijklmnop"
AWS_LIKE = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
DB_URL_WITH_PW = "postgresql+psycopg2://app:" + "Sup3rS3cret" + "Pw@db:5432/x"
SECRET_ASSIGNMENT = "JWT_SECRET" + "_KEY = 'a1b2c3d4e5f6a7b8c9d0'"


def _git_repo(tmp_path, files):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return repo


def _zip_of(tmp_path, files, name="a.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        for rel, content in files.items():
            zf.writestr(rel, content)
    return path


# ----------------------------------------------------------- the real archive

def test_real_repository_archive_builds_and_validates_clean(tmp_path):
    archive = pkg.build_archive(tmp_path / "release.zip")
    report = pkg.validate_archive(archive)

    assert report.ok, [str(f) for f in report.findings]
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())

    assert ".env.example" in names
    assert "README.md" in names
    assert "requirements.txt" in names
    assert "server/server.py" in names
    assert not any(n == ".env" or n.endswith("/.env") for n in names)
    assert not any(n.startswith(("certs/", "logs/", "storage_blobs/", ".git/")) for n in names)
    assert not any(n.endswith((".key", ".pem", ".pyc", ".apk")) for n in names)


def test_real_archive_contains_none_of_this_machines_live_secrets(tmp_path):
    archive = pkg.build_archive(tmp_path / "release.zip")
    live = pkg.live_secret_values()

    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            blob = zf.read(info)
            for value in live:
                assert value not in blob, f"live secret value found in {info.filename}"


def test_cli_verify_accepts_a_clean_archive_and_prints_no_secrets(tmp_path, capsys):
    archive = pkg.build_archive(tmp_path / "release.zip")

    assert pkg.main(["--verify", str(archive)]) == 0

    out = capsys.readouterr()
    for value in pkg.live_secret_values():
        assert value.decode() not in out.out + out.err


# ------------------------------- defence in depth: Git is not the only barrier

def test_a_repository_without_gitignore_still_cannot_leak_env_or_keys(tmp_path):
    repo = _git_repo(tmp_path, {
        "app.py": "print('hello')\n",
        ".env": f"JWT_SECRET_KEY={FAKE_SECRET}\n",
        ".env.example": "JWT_SECRET_KEY=REPLACE_WITH_A_LONG_RANDOM_SECRET\n",
        "certs/dev/server.key": PRIVATE_KEY_BLOCK,
        "certs/dev/ca.crt": CERTIFICATE,
        "backup.dump": b"\x00PGDMP",
        "logs/server.log": "token=abc\n",
    })

    archive = pkg.build_archive(tmp_path / "out.zip", root=repo)

    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
    assert "app.py" in names
    assert ".env.example" in names
    assert ".env" not in names
    assert "certs/dev/server.key" not in names
    assert "backup.dump" not in names
    assert "logs/server.log" not in names
    assert pkg.validate_archive(archive, live=[]).ok


def test_a_live_secret_pasted_into_a_source_file_fails_validation(tmp_path):
    (tmp_path / "home").mkdir()
    repo = _git_repo(tmp_path, {
        ".env": f"DATABASE_URL=postgresql+psycopg2://qrscs_app:{FAKE_SECRET}@localhost:5432/qrscs\n",
        "notes.md": f"the db password is {FAKE_SECRET}\n",
    })
    live = pkg.live_secret_values(repo)
    assert FAKE_SECRET.encode() in live

    archive = pkg.build_archive(tmp_path / "out.zip", root=repo)
    report = pkg.validate_archive(archive, live=live)

    assert not report.ok
    assert [f.path for f in report.findings] == ["notes.md"]
    assert FAKE_SECRET not in str(report.findings[0])


# --------------------------------------------------------------- the validator

@pytest.mark.parametrize(
    "rel, content, expected_rule",
    [
        (".env", "X=1\n", "forbidden file name"),
        ("config/prod.env", "X=1\n", "forbidden file name"),
        ("certs/dev/ca.key", "x", "forbidden directory"),
        ("keys/server.pem", "x", "forbidden file name"),
        ("data/users.sqlite", b"SQLite", "forbidden file name"),
        ("build/app-debug.apk", b"PK", "forbidden file name"),
        ("src/__pycache__/m.pyc", b"\x00", "forbidden directory"),
        ("notes.txt", RSA_KEY_START, "private-key block"),
        ("notes.txt", "token " + JWT_LIKE, "JWT-shaped token"),
        ("settings.py", "URL = '" + DB_URL_WITH_PW + "'", "database URL with password"),
        ("settings.py", SECRET_ASSIGNMENT, "secret assignment"),
        ("cloud.txt", AWS_LIKE, "AWS access key id"),
    ],
)
def test_validator_rejects_hostile_archives(tmp_path, rel, content, expected_rule):
    archive = _zip_of(tmp_path, {"ok.txt": "fine", rel: content})

    report = pkg.validate_archive(archive, live=[])

    assert not report.ok
    assert any(expected_rule in f.rule for f in report.findings), [str(f) for f in report.findings]


@pytest.mark.parametrize(
    "rel, content",
    [
        (".env.example", "JWT_SECRET_KEY=REPLACE_WITH_A_LONG_RANDOM_SECRET\nDATABASE_URL=postgresql+psycopg2://qrscs_app:REPLACE_PASSWORD@localhost/qrscs\n"),
        ("certs/dev/ca.crt", CERTIFICATE),
        ("config_server.py", "'Example: postgresql+psycopg2://user:pass@host:5432/dbname'"),
        ("docs/x.md", "export JWT_SECRET_KEY=<your secret here>\n"),
        ("cfg.py", "JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', '')\n"),
    ],
)
def test_validator_accepts_documented_placeholders_and_public_certificates(tmp_path, rel, content):
    archive = _zip_of(tmp_path, {rel: content})

    assert pkg.validate_archive(archive, live=[]).ok


def test_failed_build_deletes_the_archive_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path, {"notes.md": PRIVATE_KEY_BLOCK})
    monkeypatch.setattr(pkg, "ROOT", repo)
    target = tmp_path / "bad.zip"

    assert pkg.main(["--output", str(target)]) == 1

    assert not target.exists()
    assert "notes.md: private-key block" in capsys.readouterr().err
