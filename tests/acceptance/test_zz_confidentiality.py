"""Nothing sensitive may be at rest on the server side.

Runs LAST in the acceptance session (the file name sorts after every other module). By then the run
has sent real messages, files, registrations and logins, so this inspects what the server, the
database and the blob store actually hold. Only counts and locations are reported -- never a value.
"""

import base64
import json

from sqlalchemy import create_engine, text

import acceptance_db
from tests.acceptance import evidence

MINIMUM_PLAINTEXTS = 10  # the scan is only meaningful if the run really sent things


def _forms(needle: bytes) -> list[bytes]:
    """The ways a value could appear in a log, a JSON dump of a row, or a base64 column."""
    forms = {needle, needle.hex().encode(), base64.b64encode(needle)}
    return [f for f in forms if len(f) >= 8]


def find_hits(label: str, data: bytes, needle_groups: dict[str, list[bytes]]) -> list[str]:
    hits = []
    lowered = data.lower()
    for category, needles in needle_groups.items():
        for needle in needles:
            for form in _forms(needle):
                if form in data or form.lower() in lowered:
                    hits.append(f"{category} found in {label}")
                    break
    return sorted(set(hits))


def test_the_scanner_finds_what_it_is_looking_for():
    groups = {"message plaintext": [b"a-very-specific-plaintext"]}

    assert find_hits("planted", b"xx a-very-specific-plaintext yy", groups)
    assert find_hits("planted-hex", b"xx " + b"a-very-specific-plaintext".hex().encode() + b" yy", groups)
    assert not find_hits("clean", b"nothing to see here", groups)


def test_logs_database_and_blobs_hold_no_plaintext_password_or_key_material(stack, run_dir):
    assert len(evidence.PLAINTEXT) >= MINIMUM_PLAINTEXTS, (
        f"only {len(evidence.PLAINTEXT)} plaintext messages were recorded; run the whole acceptance suite"
    )
    assert evidence.PASSWORDS
    groups = evidence.needles()
    hits = []

    # 1. Logs written by this run.
    log_bytes = 0
    for label, data in stack.logs_written_by_this_run():
        log_bytes += len(data)
        hits += find_hits(label, data, groups)
    assert log_bytes > 0, "no log output was found to inspect"

    # 2. Every row of every table, as the application role sees it.
    engine = create_engine(acceptance_db.urls()[0], future=True)
    rows_scanned = 0
    ciphertext_messages = 0
    with engine.connect() as connection:
        tables = [r[0] for r in connection.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
        ))]
        for table in tables:
            if table == "alembic_version":
                continue
            for (row_json,) in connection.execute(text(f'SELECT row_to_json(t)::text FROM "{table}" t')):
                rows_scanned += 1
                hits += find_hits(f"database table {table}", row_json.encode("utf-8"), groups)
        ciphertext_messages = connection.execute(text("SELECT count(*) FROM messages")).scalar()
        totals = {
            name: connection.execute(text(f'SELECT count(*) FROM "{table}"')).scalar()
            for name, table in (("users", "users"), ("conversations", "conversations"), ("messages", "messages"),
                                ("message_recipients", "message_recipients"), ("devices", "devices"))
        }
    engine.dispose()
    # Counts only (no content): evidence of how much the run actually did.
    (run_dir / "database_summary.json").write_text(json.dumps(totals, indent=2), encoding="utf-8")
    assert rows_scanned > 0 and ciphertext_messages > 0, "the database held nothing to inspect"

    # 3. The encrypted blob store.
    blob_files = [p for p in stack.blob_dir.rglob("*") if p.is_file()]
    for path in blob_files:
        hits += find_hits("an encrypted blob", path.read_bytes(), groups)

    scan = {
        "log_bytes_scanned": log_bytes,
        "database_rows_scanned": rows_scanned,
        "database_messages": ciphertext_messages,
        "blobs_scanned": len(blob_files),
        "patterns": {category: len(values) for category, values in groups.items()},
        "hits": sorted(set(hits)),
    }
    (run_dir / "confidentiality_scan.json").write_text(json.dumps(scan, indent=2), encoding="utf-8")
    print(f"scanned {log_bytes} log bytes, {rows_scanned} database rows ({ciphertext_messages} messages), "
          f"{len(blob_files)} blobs against {sum(len(v) for v in groups.values())} patterns")
    assert not hits, sorted(set(hits))
