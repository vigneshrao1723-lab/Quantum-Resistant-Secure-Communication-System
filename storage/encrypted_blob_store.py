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

import re
import uuid

from config_server import FILE_STORAGE_ROOT

# A reference is a uuid4().hex produced by store_blob() below -- 32
# lowercase hex characters, nothing else, ever.
_REFERENCE_PATTERN = re.compile(r"\A[0-9a-f]{32}\Z")


class InvalidBlobReference(ValueError):
    """
    A blob reference that is not the exact shape store_blob() emits
    (D8 / P1).

    Raised rather than returning a path, so a bad reference can never
    reach the filesystem at all.
    """


def _path_for(reference: str):
    """
    Resolve a reference to its on-disk path, refusing anything that
    could escape FILE_STORAGE_ROOT (D8 / P1).

    The previous implementation was a bare ``FILE_STORAGE_ROOT /
    reference``, which trusts the reference completely. That was not
    exploitable in practice -- every caller passes either a freshly
    generated uuid4().hex or a blob_ref read back from the database,
    and the download handler validates the message id and the
    caller's conversation membership first -- but the containment was
    an argument about callers rather than a property of this module.
    Two things could defeat it if a reference ever became attacker-
    influenced (a future caller, or a tampered database row):

        FILE_STORAGE_ROOT / "../../secrets"   -> escapes upward
        FILE_STORAGE_ROOT / "C:/Windows/x"    -> pathlib DISCARDS the
        FILE_STORAGE_ROOT / "//host/share/x"     left operand entirely
                                                 for an absolute or
                                                 UNC right operand

    Both are now impossible: the reference must match the exact
    generated shape, and the resolved path is checked to still be
    inside the root afterwards. The format check alone would be
    sufficient; the containment check is kept as well so that
    loosening the format later cannot silently reopen the escape.
    """

    if not isinstance(reference, str) or not _REFERENCE_PATTERN.match(reference):
        raise InvalidBlobReference(
            f"Blob reference is not a valid 32-character hex identifier: "
            f"{reference!r}"
        )

    root = FILE_STORAGE_ROOT.resolve()
    candidate = (root / reference).resolve()

    # is_relative_to() rather than a string prefix comparison: a
    # prefix test would accept a sibling directory whose name merely
    # starts with the root's name.
    if not candidate.is_relative_to(root):
        raise InvalidBlobReference(
            f"Blob reference resolves outside the storage root: {reference!r}"
        )

    return candidate


def store_blob(data: bytes) -> str:
    """Persist an opaque encrypted blob, returning its reference."""

    FILE_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

    reference = uuid.uuid4().hex

    # _path_for() validates even this self-generated reference, so the
    # write path and the read path share one definition of what a
    # legal reference is rather than only agreeing by convention.
    _path_for(reference).write_bytes(data)

    return reference


def load_blob(reference: str) -> bytes:
    """Retrieve a previously stored blob by its reference."""

    return _path_for(reference).read_bytes()


def delete_blob(reference: str) -> None:
    """
    Remove a previously stored blob. A no-op if it is already gone.

    An unrecognised reference is also a no-op, deliberately
    asymmetric with store_blob()/load_blob(), which raise
    InvalidBlobReference (D8 / P1).

    The reason is the contract this function already had and that
    tests/test_file_payload_pipeline.py pins: deletion is
    idempotent. Raising out of a cleanup path is worse than
    useless -- it aborts whatever unrelated work was tidying up.
    Asking to delete something that cannot exist is a request that
    is already satisfied.

    Containment is NOT weakened by this: the early return happens
    instead of touching the filesystem, so no path outside
    FILE_STORAGE_ROOT is ever unlinked -- which is the property
    that matters. Reading or writing a bad reference still fails
    loudly, because there a silent no-op would hide a real bug.
    """

    try:
        path = _path_for(reference)
    except InvalidBlobReference:
        return

    path.unlink(missing_ok=True)
