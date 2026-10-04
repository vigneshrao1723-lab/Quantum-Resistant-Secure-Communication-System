"""
Tests for Phase 6 (Secure File & Image Transfer Infrastructure)'s
foundation:

  - domain/payload_type.py: FILE/IMAGE members, BLOB_STORAGE_PAYLOAD_TYPES
  - domain/payload_serializer.py: binary passthrough branch
  - payload/file_adapter.py: FilePayloadAdapter (delegates to
    crypto/payload_cipher.py, unmodified)
  - storage/encrypted_blob_store.py: the generic, payload-agnostic
    blob backend

Server-side routing (persist_message() storing FILE/IMAGE ciphertext
via encrypted_blob_store instead of inline) is covered by
tests/test_message_persistence_integration.py, against the real
handle_client accept loop.

Run with:
    pytest tests/test_file_payload_pipeline.py -v
"""

import pytest

from crypto.aes import AESCipher
from domain.payload import Payload
from domain.payload_serializer import deserialize_payload, serialize_payload
from domain.payload_type import BLOB_STORAGE_PAYLOAD_TYPES, PayloadType, classify_attachment
from payload.file_adapter import FilePayloadAdapter

VALID_KEY = b"K" * 32


# =====================================================
# domain/payload_type.py -- classification
# =====================================================

def test_blob_storage_payload_types_contains_file_and_image():
    assert PayloadType.FILE in BLOB_STORAGE_PAYLOAD_TYPES
    assert PayloadType.IMAGE in BLOB_STORAGE_PAYLOAD_TYPES


def test_blob_storage_payload_types_excludes_text():
    assert PayloadType.TEXT not in BLOB_STORAGE_PAYLOAD_TYPES


# =====================================================
# Phase 19.24 -- Voice/Video Messages: NOT a new payload pipeline --
# just two more PayloadType members routed through the exact same
# blob-storage/adapter machinery FILE/IMAGE already use (see domain/
# payload_type.py's own module docstring). These assert that reuse is
# real, not merely claimed.
# =====================================================

def test_blob_storage_payload_types_contains_voice_and_video():
    assert PayloadType.VOICE in BLOB_STORAGE_PAYLOAD_TYPES
    assert PayloadType.VIDEO in BLOB_STORAGE_PAYLOAD_TYPES


@pytest.mark.parametrize("filename,expected", [
    ("clip.m4a", PayloadType.VOICE),
    ("clip.ogg", PayloadType.VOICE),
    ("clip.wav", PayloadType.VOICE),
    ("clip.mp4", PayloadType.VIDEO),
    ("clip.webm", PayloadType.VIDEO),
    ("photo.png", PayloadType.IMAGE),
    ("photo.webp", PayloadType.IMAGE),
    ("document.pdf", PayloadType.FILE),
    ("no_extension_at_all", PayloadType.FILE),
])
def test_classify_attachment(filename, expected):
    assert classify_attachment(filename) == expected


# =====================================================
# domain/payload_serializer.py -- binary passthrough
# =====================================================

@pytest.mark.parametrize(
    "payload_type",
    [PayloadType.FILE, PayloadType.IMAGE, PayloadType.VOICE, PayloadType.VIDEO],
)
def test_serialize_deserialize_binary_round_trip(payload_type):
    raw_bytes = b"\x00\x01\xffnot-utf8-safe-binary-content"
    payload = Payload(payload_type=payload_type, content=raw_bytes)

    data = serialize_payload(payload)

    assert data == raw_bytes
    assert deserialize_payload(payload_type, data) == raw_bytes


# =====================================================
# payload/file_adapter.py
# =====================================================

@pytest.mark.parametrize(
    "payload_type",
    [PayloadType.FILE, PayloadType.IMAGE, PayloadType.VOICE, PayloadType.VIDEO],
)
def test_file_adapter_encrypt_decrypt_round_trip(payload_type):
    aes = AESCipher(VALID_KEY)
    adapter = FilePayloadAdapter(payload_type)
    raw_bytes = b"binary file content \x00\x01\x02"

    envelope = adapter.encrypt(raw_bytes, aes, content_metadata={"filename": "a.bin"})

    assert envelope.payload_type == payload_type
    assert envelope.content_metadata == {"filename": "a.bin"}

    recovered = adapter.decrypt(envelope, AESCipher(VALID_KEY))

    assert recovered == raw_bytes


def test_file_adapter_generic_ciphertext_differs_from_raw_bytes_as_string():
    """FilePayloadAdapter delegates to crypto/payload_cipher.py's
    generic (base64-based) strategy, not TextPayloadAdapter's
    compatibility strategy -- decrypting its ciphertext with plain
    AESCipher must not directly yield the original bytes as text."""
    aes = AESCipher(VALID_KEY)
    adapter = FilePayloadAdapter(PayloadType.FILE)

    envelope = adapter.encrypt(b"some file bytes", aes)

    assert AESCipher(VALID_KEY).decrypt(envelope.ciphertext) != "some file bytes"


# =====================================================
# storage/encrypted_blob_store.py -- generic blob backend
# =====================================================

@pytest.fixture()
def isolated_blob_store(tmp_path, monkeypatch):
    """Point the blob store at a throwaway directory so tests never
    touch the real FILE_STORAGE_ROOT."""
    from storage import encrypted_blob_store

    monkeypatch.setattr(encrypted_blob_store, "FILE_STORAGE_ROOT", tmp_path)
    return encrypted_blob_store


def test_store_and_load_blob_round_trip(isolated_blob_store):
    reference = isolated_blob_store.store_blob(b"opaque encrypted bytes")

    assert isolated_blob_store.load_blob(reference) == b"opaque encrypted bytes"


def test_store_blob_creates_storage_root_on_first_use(isolated_blob_store, tmp_path):
    empty_root = tmp_path / "does-not-exist-yet"
    isolated_blob_store.FILE_STORAGE_ROOT = empty_root

    isolated_blob_store.store_blob(b"anything")

    assert empty_root.is_dir()


def test_each_store_blob_call_gets_a_distinct_reference(isolated_blob_store):
    first = isolated_blob_store.store_blob(b"content A")
    second = isolated_blob_store.store_blob(b"content B")

    assert first != second
    assert isolated_blob_store.load_blob(first) == b"content A"
    assert isolated_blob_store.load_blob(second) == b"content B"


def test_delete_blob_removes_it(isolated_blob_store):
    reference = isolated_blob_store.store_blob(b"to be deleted")

    isolated_blob_store.delete_blob(reference)

    with pytest.raises(FileNotFoundError):
        isolated_blob_store.load_blob(reference)


def test_delete_blob_is_a_no_op_when_absent(isolated_blob_store):
    isolated_blob_store.delete_blob("no-such-reference")  # must not raise


def test_blob_store_is_payload_agnostic():
    """The module's public surface takes/returns only bytes and opaque
    reference strings -- no parameter or return value is shaped around
    payload_type, filename, or any other content-specific concept."""
    import inspect

    from storage import encrypted_blob_store

    for name in ("store_blob", "load_blob", "delete_blob"):
        signature = inspect.signature(getattr(encrypted_blob_store, name))
        for param_name in signature.parameters:
            assert param_name in ("data", "reference")
