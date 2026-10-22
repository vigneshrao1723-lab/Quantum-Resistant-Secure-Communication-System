"""In-memory record of what the acceptance run sent and generated, for the confidentiality scan.

Nothing here is ever written to disk or printed: it exists so the final scan can prove that none
of it appears in server logs, the database or the blob store.
"""

from __future__ import annotations

import base64

PLAINTEXT: set[str] = set()       # message / file text that was sent
PASSWORDS: set[str] = set()       # account passwords created by the run
KEY_MATERIAL: set[str] = set()    # base64 of identity secret keys and conversation keys read from browsers
BINARY_FILES: list[bytes] = []    # raw attachment contents that were sent


def record_plaintext(text: str):
    if text and len(text) >= 8:
        PLAINTEXT.add(text)


def record_password(password: str):
    PASSWORDS.add(password)


def record_key_material(base64_values):
    for value in base64_values:
        if value and len(value) >= 16:
            KEY_MATERIAL.add(value)


def record_file(content: bytes):
    BINARY_FILES.append(content)


def needles() -> dict[str, list[bytes]]:
    """Every byte pattern that must never appear, grouped by what it is."""
    out: dict[str, list[bytes]] = {"message plaintext": [], "password": [], "key material": [], "attachment": []}
    for text in PLAINTEXT:
        out["message plaintext"].append(text.encode("utf-8"))
    for password in PASSWORDS:
        out["password"].append(password.encode("utf-8"))
    for value in KEY_MATERIAL:
        out["key material"].append(value.encode("ascii"))
        try:
            raw = base64.b64decode(value)
            out["key material"].append(raw.hex().encode("ascii"))
            out["key material"].append(raw)
        except Exception:
            pass
    for content in BINARY_FILES:
        out["attachment"].append(content[:4096] if len(content) > 4096 else content)
    return out
