"""
Encrypted blob storage.

The generic, payload-agnostic storage backend for encrypted payload
content too large to store inline in messages.ciphertext (Phase 6 --
Secure File & Image Transfer Infrastructure). Stores and retrieves
opaque encrypted bytes only -- it has no notion of payload_type,
filename, mime type, or any other content-specific concept. That
differentiation lives entirely in PayloadType, content_metadata, and
PayloadAdapter (see domain/payload_type.py's BLOB_STORAGE_PAYLOAD_TYPES
for which payload types use this module at all). A file, an image, and
any future binary payload type all call store_blob() with different
bytes and get back a reference in exactly the same shape -- every
future binary payload type reuses this same implementation unchanged.

References are opaque strings from every caller's perspective (see
database/models/message.py's blob_ref column docstring for why it is
documented as an implementation detail of this specific backend) --
today, a UUID4 hex string that doubles as the on-disk filename under
FILE_STORAGE_ROOT.
"""

import uuid

from config_server import FILE_STORAGE_ROOT


def _path_for(reference: str):
    return FILE_STORAGE_ROOT / reference


def store_blob(data: bytes) -> str:
    """Persist an opaque encrypted blob, returning its reference."""

    FILE_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

    reference = uuid.uuid4().hex

    _path_for(reference).write_bytes(data)

    return reference


def load_blob(reference: str) -> bytes:
    """Retrieve a previously stored blob by its reference."""

    return _path_for(reference).read_bytes()


def delete_blob(reference: str) -> None:
    """Remove a previously stored blob. A no-op if it is already gone."""

    _path_for(reference).unlink(missing_ok=True)
