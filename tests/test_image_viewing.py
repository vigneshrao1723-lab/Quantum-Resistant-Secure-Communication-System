"""
BUG 5 -- viewing a received image.

Sending images already worked end to end: the bytes arrive intact, the
blob is persisted as ciphertext, and the filename/MIME metadata
survives. What did not work was viewing one. ImageMessageBubble
rendered a fixed 320px-wide thumbnail from the decrypted bytes and
then discarded those bytes entirely -- it kept only ``kind``,
``_timestamp_text`` and ``time_label`` -- so there was nothing to open
at full size and nothing to save, and no button or click handler
offering either. A small image was additionally upscaled to 320px
wide, which is why a shared screenshot looked wrong rather than merely
small.

FileMessageBubble already had the right shape for this: hold the
decrypted bytes in memory and write them to disk only when the user
explicitly asks. These tests hold the image bubble to the same
contract, plus an in-app viewer so the common case (just look at it)
needs no disk write at all.

The byte comparisons use real image fixtures -- genuine PNG and JPEG
files produced by Qt at test time, loadable by QPixmap -- rather than
stub byte strings, so "the saved file is the image that was sent" is
actually being asserted. They are generated rather than committed so
no binary lives in the repository.

Run with:
    pytest tests/test_image_viewing.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
import uuid

import pytest
from PySide6.QtGui import QColor, QImage
from PySide6.QtWidgets import QApplication, QPushButton

import client.session as client_session_module
from auth.authentication_service import AuthenticationService
from auth.schemas import LoginRequest, RegisterRequest
from client.session import ClientSession
from crypto.key_manager import fingerprint_combined_identity
from database.connection import SessionLocal
from database.models.message import Message
from database.repositories.session_repository import SessionRepository
from database.repositories.user_repository import UserRepository
from domain.conversation_summary import ConversationSummary
from domain.payload_type import PayloadType
from gui.message_widget import ImageMessageBubble, MessageWidget
from storage import encrypted_blob_store
from storage.secure_key_store import SecureKeyStore
from tests.tls_test_support import start_test_server

_app = QApplication.instance() or QApplication([])


# ----------------------------------------------------------------------
# Real image fixtures
# ----------------------------------------------------------------------


def _write_real_image(path, fmt):
    """A genuine image file written by Qt -- real PNG/JPEG bytes with
    real headers, not a hand-rolled stub."""

    image = QImage(80, 60, QImage.Format_RGB32)

    for y in range(60):
        for x in range(80):
            image.setPixelColor(x, y, QColor((x * 3) % 256, (y * 4) % 256, 200))

    assert image.save(str(path), fmt), f"could not write a real {fmt}"

    return path.read_bytes()


@pytest.fixture()
def png_file(tmp_path):
    path = tmp_path / "holiday.png"
    return path, _write_real_image(path, "PNG")


@pytest.fixture()
def jpeg_file(tmp_path):
    path = tmp_path / "holiday.jpg"
    return path, _write_real_image(path, "JPEG")


# ----------------------------------------------------------------------
# Bubble-level: the defect itself
# ----------------------------------------------------------------------


def _buttons(bubble):
    return {button.text() for button in bubble.findChildren(QPushButton)}


def test_image_bubble_retains_the_original_bytes(png_file):
    """The bubble used to throw the decrypted bytes away after
    building a thumbnail, which is why nothing could offer to open or
    save the image."""

    _path, original = png_file
    bubble = ImageMessageBubble(original, kind="received", sender="alice")

    assert bubble.image_bytes == original


def test_image_bubble_offers_view_and_save_actions(png_file):
    _path, original = png_file
    bubble = ImageMessageBubble(original, kind="received", sender="alice")

    assert _buttons(bubble) == {"View", "Save As..."}


def test_thumbnail_never_upscales_a_small_image(png_file):
    """A 80px-wide image was being blown up to 320px wide, which is
    what made a shared image look wrong rather than just small."""

    _path, original = png_file
    bubble = ImageMessageBubble(original, kind="received", sender="alice")

    assert bubble.thumbnail_width() == 80


def test_thumbnail_still_scales_a_large_image_down(tmp_path):
    large = tmp_path / "large.png"
    image = QImage(1000, 400, QImage.Format_RGB32)
    image.fill(QColor(10, 20, 30))
    assert image.save(str(large), "PNG")

    bubble = ImageMessageBubble(
        large.read_bytes(), kind="received", sender="alice"
    )

    assert bubble.thumbnail_width() == ImageMessageBubble.MAX_THUMBNAIL_WIDTH


def test_view_shows_the_image_at_full_resolution(png_file):
    """Viewing must show the real image, not the thumbnail -- and must
    not write anything to disk to do it."""

    _path, original = png_file
    bubble = ImageMessageBubble(original, kind="received", sender="alice")

    viewer = bubble.open_viewer()

    try:
        assert viewer is not None
        assert bubble.full_size() == (80, 60)
    finally:
        viewer.close()


def test_save_as_writes_the_exact_original_image_bytes(png_file, tmp_path, monkeypatch):
    _path, original = png_file
    destination = tmp_path / "saved-copy.png"

    bubble = ImageMessageBubble(
        original,
        kind="received",
        sender="alice",
        content_metadata={"filename": "holiday.png", "mime_type": "image/png"},
    )

    monkeypatch.setattr(
        "gui.message_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(destination), "PNG (*.png)"),
    )

    bubble._handle_save_as()

    assert destination.exists()
    assert destination.read_bytes() == original


def test_save_as_defaults_to_the_original_filename(png_file, monkeypatch):
    """The filename travels in content_metadata all the way from the
    sender; the save dialog must offer it rather than an invented
    name."""

    _path, original = png_file
    captured = {}

    bubble = ImageMessageBubble(
        original,
        kind="received",
        sender="alice",
        content_metadata={"filename": "holiday.png", "mime_type": "image/png"},
    )

    def _capture(parent, caption, suggested, *args, **kwargs):
        captured["suggested"] = suggested
        return ("", "")

    monkeypatch.setattr(
        "gui.message_widget.QFileDialog.getSaveFileName", _capture
    )

    bubble._handle_save_as()

    assert "holiday.png" in captured["suggested"]


def test_save_as_does_nothing_when_cancelled(png_file, tmp_path, monkeypatch):
    _path, original = png_file
    bubble = ImageMessageBubble(original, kind="received", sender="alice")

    monkeypatch.setattr(
        "gui.message_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: ("", ""),
    )

    bubble._handle_save_as()

    assert list(tmp_path.glob("*.png")) == [_path]


def test_undecryptable_image_offers_no_actions():
    """An attachment whose key this client never received renders the
    existing placeholder and must not offer to view or save bytes it
    does not have."""

    bubble = ImageMessageBubble(None, kind="received", sender="alice")

    assert bubble.image_bytes is None
    assert _buttons(bubble) == set()
    assert bubble.open_viewer() is None


def test_sent_and_received_images_both_carry_metadata(png_file):
    _path, original = png_file
    metadata = {"filename": "holiday.png", "mime_type": "image/png"}

    widget = MessageWidget()
    widget.add_received_image("alice", original, content_metadata=metadata)
    widget.add_sent_image(original, content_metadata=metadata)

    received = widget.itemWidget(widget.item(0))
    sent = widget.itemWidget(widget.item(1))

    assert received.image_bytes == original
    assert sent.image_bytes == original
    assert received.content_metadata["filename"] == "holiday.png"
    assert sent.content_metadata["filename"] == "holiday.png"


# ----------------------------------------------------------------------
# End to end: a real image, sent and then actually viewed
# ----------------------------------------------------------------------


def _register(hint):
    db = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:10]
        payload = {
            "full_name": "Image Viewing Test",
            "username": f"imgv_{hint}{suffix}",
            "email": f"imgv_{hint}{suffix}@example.com",
            "password": "Str0ng!Passw0rd",
            "confirm_password": "Str0ng!Passw0rd",
            "phone_number": f"+91{uuid.uuid4().int % 10**12:012d}",
        }
        result = AuthenticationService(db).register_user(RegisterRequest(**payload))
        assert result.success, result.errors
        payload["user_id"] = result.user_id
        return payload
    finally:
        db.close()


def _delete(username):
    db = SessionLocal()
    try:
        user = UserRepository(db).get_by_username(username)
        if user is not None:
            for session in SessionRepository(db).get_active_sessions_for_user(user.id):
                db.delete(session)
            db.delete(user)
            db.commit()
    finally:
        db.close()


def _token(payload):
    db = SessionLocal()
    try:
        result = AuthenticationService(db).authenticate_user(
            LoginRequest(identifier=payload["phone_number"], password=payload["password"])
        )
        assert result.success, result.errors
        return result.token_pair.access_token
    finally:
        db.close()


def _wait_for(predicate, attempts=200, interval=0.05):
    for _ in range(attempts):
        if predicate():
            return True
        _app.processEvents()
        time.sleep(interval)
    return predicate()


@pytest.fixture()
def running_server():
    harness = start_test_server()

    yield harness

    harness.shutdown()


@pytest.fixture()
def chat(running_server, monkeypatch, tmp_path):
    """Two connected sessions plus cleanup of accounts and blobs."""

    _state, port = running_server
    monkeypatch.setattr(client_session_module, "SERVER_PORT", port)

    key_store_dir = tmp_path / "keystores"

    created = []
    opened = []
    blobs = []

    def _connect(payload):
        session = ClientSession()
        session.user_id = payload["user_id"]
        session.access_token = _token(payload)
        session.connect()
        session.login(payload["username"])
        # Server-Untrusted Identity Verification, Stage 3: this
        # lighter connect()-only pattern skips authenticate_credentials(),
        # the only place a key store is normally unlocked -- unlock a
        # real, isolated, on-disk one here too, so establish_session_key()
        # / handle_direct_key_redelivery_required() below can verify
        # whichever peer they need to. Done BEFORE send_public_key(),
        # exactly like authenticate_credentials()'s own
        # _unlock_key_store(), so a reconnecting session (Stage 2.5)
        # broadcasts the SAME persisted identity key instead of a
        # fresh ephemeral one that would look like a KEY_CHANGED to an
        # already-verified peer.
        #
        # Protocol-Level ML-DSA Origin Authentication: also loads/
        # persists the signing keypair (identity/key-persistence
        # foundation phase), for the identical reason -- send_public_key()
        # now always attaches an ML-DSA signature, so a reconnecting
        # session whose SIGNING key was left ephemeral would look like
        # a KEY_CHANGED to an already-verified peer even with its KEM
        # key correctly persisted.
        session.key_store = SecureKeyStore(
            payload["user_id"], storage_dir=key_store_dir / payload["username"]
        )
        session.key_store.unlock(payload["password"])
        session.key_manager.load_or_create_kyber_keypair(session.key_store)
        session.key_manager.load_or_create_signing_keypair(session.key_store)
        session.send_public_key()
        session.start_receiver()
        opened.append(session)
        return session

    alice_payload = _register("alice_")
    bob_payload = _register("bob_")
    created.extend([alice_payload, bob_payload])

    alice = _connect(alice_payload)
    bob = _connect(bob_payload)

    assert _wait_for(
        lambda: alice.key_manager.get_public_key(bob_payload["username"]) is not None
    )
    assert _wait_for(
        lambda: bob.key_manager.get_public_key(alice_payload["username"]) is not None
    )

    # Alice sends the image, then a direct-key-redelivery on Bob's
    # reconnect -- so Alice needs Bob verified. Phase 13 (Group-Key-
    # Distribution ML-DSA Origin Authentication): Bob is also the
    # RECEIVER of that group_key_distribution packet, which now
    # separately requires Bob to have Alice already VERIFIED too.
    alice.key_store.verify_peer_fingerprint(
        bob_payload["username"],
        fingerprint_combined_identity(
            bob.key_manager.public_key, bob.key_manager.ml_dsa.export_public_key()
        ),
    )
    bob.key_store.verify_peer_fingerprint(
        alice_payload["username"],
        fingerprint_combined_identity(
            alice.key_manager.public_key, alice.key_manager.ml_dsa.export_public_key()
        ),
    )

    yield {
        "alice": alice,
        "bob": bob,
        "alice_name": alice_payload["username"],
        "bob_name": bob_payload["username"],
        "bob_payload": bob_payload,
        "connect": _connect,
        "blobs": blobs,
    }

    for session in opened:
        try:
            session.disconnect()
        except Exception:  # noqa: BLE001 -- teardown must not mask a failure
            pass

    for reference in blobs:
        try:
            encrypted_blob_store.delete_blob(reference)
        except Exception:  # noqa: BLE001
            pass

    for payload in created:
        _delete(payload["username"])


def _open_direct(session, partner):
    session.set_current_chat(
        ConversationSummary(
            conversation_id=None,
            username=partner,
            is_online=True,
            latest_message=None,
        )
    )


def _track_blob(chat, conversation_id):
    db = SessionLocal()
    try:
        row = (
            db.query(Message)
            .filter(Message.conversation_id == uuid.UUID(str(conversation_id)))
            .order_by(Message.timestamp.desc())
            .first()
        )
        if row is not None and row.blob_ref:
            chat["blobs"].append(row.blob_ref)
        return row
    finally:
        db.close()


@pytest.mark.parametrize("fixture_name", ["png_file", "jpeg_file"])
def test_received_image_is_viewable_and_saves_identical_bytes(
    chat, request, fixture_name, tmp_path, monkeypatch
):
    """The whole point of BUG 5: Alice sends a real image, Bob can
    actually look at it, and saving it yields the original file."""

    path, original = request.getfixturevalue(fixture_name)

    alice, bob = chat["alice"], chat["bob"]
    received = []
    # Signal order is (identity_key, sender, payload_type, content,
    # content_metadata) -- see ClientSession.handle_chat()'s emit.
    bob.payload_message_received.connect(
        lambda _key, sender, payload_type, content, metadata: received.append(
            (sender, payload_type, content, metadata)
        )
    )

    _open_direct(alice, chat["bob_name"])
    _open_direct(bob, chat["alice_name"])
    alice.send_attachment(str(path))

    assert _wait_for(lambda: received), "the image never reached Bob"
    _track_blob(chat, alice.current_conversation_id)

    _sender, payload_type, content, metadata = received[0]
    assert payload_type == PayloadType.IMAGE
    assert content == original
    assert metadata["filename"] == path.name

    # Render it the way ChatWindow.receive_message() does.
    widget = MessageWidget()
    widget.add_received_image(
        chat["alice_name"], content, content_metadata=metadata
    )
    bubble = widget.itemWidget(widget.item(0))

    # Bob can look at it...
    viewer = bubble.open_viewer()
    assert viewer is not None
    viewer.close()

    # ...and save it, byte for byte.
    destination = tmp_path / f"saved-{path.name}"
    monkeypatch.setattr(
        "gui.message_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(destination), ""),
    )
    bubble._handle_save_as()

    assert destination.read_bytes() == original


def test_image_from_history_after_reconnect_is_viewable(
    chat, png_file, tmp_path, monkeypatch
):
    """Close and reopen the application, open the conversation again:
    the image must still be viewable and save identically."""

    path, original = png_file
    alice, bob = chat["alice"], chat["bob"]

    _open_direct(alice, chat["bob_name"])
    _open_direct(bob, chat["alice_name"])
    alice.send_attachment(str(path))

    conversation_id = alice.current_conversation_id
    assert _wait_for(lambda: _track_blob(chat, conversation_id) is not None)

    # Bob restarts entirely -- new session, new KeyManager.
    bob.disconnect()
    time.sleep(0.4)
    bob_restarted = chat["connect"](chat["bob_payload"])
    assert _wait_for(
        lambda: bob_restarted.key_manager.has_key(conversation_id)
    ), "direct key recovery did not restore the conversation key"

    _open_direct(bob_restarted, chat["alice_name"])
    history = bob_restarted.load_conversation_history(
        chat["alice_name"], is_group=False
    )

    images = [row for row in history if row.get("payload_type") == PayloadType.IMAGE]
    assert images, "the image was not in the reloaded history"

    entry = images[0]
    assert entry["content"] == original

    widget = MessageWidget()
    widget.add_received_image(
        chat["alice_name"],
        entry["content"],
        content_metadata=entry.get("content_metadata"),
    )
    bubble = widget.itemWidget(widget.item(0))

    viewer = bubble.open_viewer()
    assert viewer is not None
    viewer.close()

    destination = tmp_path / "from-history.png"
    monkeypatch.setattr(
        "gui.message_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(destination), ""),
    )
    bubble._handle_save_as()

    assert destination.read_bytes() == original


def test_thumbnail_bounds_a_tall_image_by_height(tmp_path):
    """A width-only bound left tall images unbounded: a 600x4000
    screenshot became 320x2133 and pushed the rest of the transcript
    off screen."""

    tall = tmp_path / "tall.png"
    image = QImage(600, 4000, QImage.Format_RGB32)
    image.fill(QColor(10, 20, 30))
    assert image.save(str(tall), "PNG")

    bubble = ImageMessageBubble(
        tall.read_bytes(), kind="received", sender="alice"
    )

    width, height = bubble.thumbnail_size()

    assert height == ImageMessageBubble.MAX_THUMBNAIL_HEIGHT
    assert width <= ImageMessageBubble.MAX_THUMBNAIL_WIDTH

    # Aspect ratio preserved, not squashed to fit the box.
    assert abs((width / height) - (600 / 4000)) < 0.01


def test_thumbnail_never_upscales_a_small_image_in_either_dimension(png_file):
    _path, original = png_file
    bubble = ImageMessageBubble(original, kind="received", sender="alice")

    width, height = bubble.thumbnail_size()

    assert (width, height) == bubble.full_size()
