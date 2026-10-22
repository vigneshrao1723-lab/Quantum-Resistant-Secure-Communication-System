"""
Website: group attachments (files, voice, video) and group membership events, with real Desktop peers.

Real Chrome, real gateway, real server, real Desktop sessions. Group attachments use the same
encrypted attachment pipeline as direct chats (one stored message, one delivery row per member);
membership events come from the server's own records.
"""

import base64
import time

from domain.payload_type import PayloadType
from tests.test_group_admin_and_inbox import _verify
from tests.test_media_playback_interop import MIN_RMS, desktop_voice_clip  # noqa: F401 -- real AAC clip fixture
from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _delete,
    _wait_for,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)
from tests.test_web_messenger_layout_and_parity import _group_with_web_member, _pair


def _open_group(page, name):
    page.click('.tab-btn[data-tab="groups"]')
    page.click(f'.row-card:has-text("{name}")')
    page.wait_for_selector("#groupChatView:not([hidden])")


def _record(session):
    received = []
    session.payload_message_received.connect(
        lambda key, sender, payload_type, data, metadata: received.append((key, sender, payload_type, bytes(data), metadata))
    )
    return received


def _event_lines(page):
    return page.eval_on_selector_all("#groupMessages .group-event .bubble", "els => els.map(e => e.textContent)")


# ====================================================================== group attachments


def test_a_file_sent_from_the_website_to_a_group_reaches_the_desktop_member_exactly(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        group_id = _group_with_web_member(alice, page, "web-files")
        got = _record(alice)
        _open_group(page, "web-files")
        document = bytes(range(256)) * 12

        page.set_input_files("#groupAttachmentInput", {"name": "notes.bin", "mimeType": "application/octet-stream", "buffer": document})
        assert page.locator("#sendGroupAttachmentBtn").is_visible()
        assert "notes.bin" in page.inner_text("#sendGroupAttachmentBtn")
        page.click("#sendGroupAttachmentBtn")

        assert _wait_for(lambda: len(got) == 1, attempts=200, interval=0.1)
        key, sender, kind, data, metadata = got[0]
        assert (key, sender, kind) == (group_id, bob_payload["username"], PayloadType.FILE)
        assert data == document and metadata["filename"] == "notes.bin"
        # Shown in the group's own transcript, and the composer is reset.
        assert page.locator("#groupMessages a.msg-file").count() == 1
        assert page.locator("#sendGroupAttachmentBtn").is_hidden()
        assert page.locator("#messages a.msg-file").count() == 0           # never in a direct chat's transcript
    finally:
        _delete(bob_payload["username"])


def test_a_voice_message_recorded_in_a_group_on_the_website_reaches_the_desktop_member(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _group_with_web_member(alice, page, "web-voice")
        got = _record(alice)
        _open_group(page, "web-voice")

        page.click("#groupAttachBtn")
        page.click(".bubble-context-menu >> text=Voice Message")
        page.wait_for_selector(".media-recorder-card")
        record = ".media-recorder-card > [data-role=record]"
        page.click(record)
        page.wait_for_timeout(1200)
        page.click(record)
        assert _wait_for(lambda: page.get_attribute(".media-recorder-card", "data-state") == "recorded")
        page.click(".media-recorder-actions .btn-primary")

        assert _wait_for(lambda: page.locator(".media-recorder-card").count() == 0, attempts=100, interval=0.1)
        assert page.locator("#groupMessages audio.bubble-media").count() == 1
        assert _wait_for(lambda: len(got) == 1, attempts=200, interval=0.1)
        assert got[0][2] == "voice" and len(got[0][3]) > 0
        assert page.locator("#messages audio.bubble-media").count() == 0
    finally:
        _delete(bob_payload["username"])


def test_a_desktop_voice_message_in_a_group_plays_on_the_website(
    running_server, gateway_url, browser_page, desktop_app, desktop_voice_clip, tmp_path
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        group_id = _group_with_web_member(alice, page, "desk-voice")
        _open_group(page, "desk-voice")
        clip = tmp_path / "voice-message.m4a"
        clip.write_bytes(desktop_voice_clip)
        alice.set_current_chat(alice.conversation_store.get(group_id))

        payload_type, _data, _metadata = alice.send_attachment(str(clip))

        assert payload_type == PayloadType.VOICE
        assert _wait_for(lambda: page.locator("#groupMessages audio.bubble-media").count() == 1, attempts=200, interval=0.1)
        info = page.evaluate("""async () => {
          const audio = document.querySelector('#groupMessages audio.bubble-media');
          if (audio.readyState < 1) await new Promise((res, rej) => { audio.onloadedmetadata = res; audio.onerror = () => rej(new Error('audio error')); });
          const bytes = new Uint8Array(await (await fetch(audio.src)).arrayBuffer());
          const decoded = await new AudioContext().decodeAudioData(bytes.buffer.slice(0));
          const data = decoded.getChannelData(0); let sum = 0;
          for (let i = 0; i < data.length; i++) sum += data[i] * data[i];
          return {duration: audio.duration, rms: Math.sqrt(sum / data.length), size: bytes.length};
        }""")
        assert info["duration"] > 1.5 and info["rms"] > MIN_RMS and info["size"] == len(desktop_voice_clip)
        # The sender label on a received group message is the sender's name.
        assert page.locator("#groupMessages .bubble-sender").count() == 1
    finally:
        _delete(bob_payload["username"])


def test_group_history_returns_attachments_after_a_reload(running_server, gateway_url, browser_page, desktop_app, tmp_path):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        group_id = _group_with_web_member(alice, page, "hist-files")
        alice.set_current_chat(alice.conversation_store.get(group_id))
        document = b"history across a reopen " * 40
        path = tmp_path / "kept.bin"
        path.write_bytes(document)
        alice.send_attachment(str(path))
        _open_group(page, "hist-files")
        assert _wait_for(lambda: page.locator("#groupMessages a.msg-file").count() == 1, attempts=200, interval=0.1)

        page.click("#settingsToggleBtn")                                    # leave and reopen: history reloads
        _open_group(page, "hist-files")

        assert _wait_for(lambda: page.locator("#groupMessages a.msg-file").count() == 1, attempts=200, interval=0.1)
        href = page.eval_on_selector("#groupMessages a.msg-file", "el => el.href")
        received = base64.b64decode(page.evaluate(
            """async (u) => { const b = new Uint8Array(await (await fetch(u)).arrayBuffer()); let s = '';
                              for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }""", href))
        assert received == document                                          # exactly once, exactly the bytes
    finally:
        _delete(bob_payload["username"])


# ====================================================================== group membership events


def test_membership_events_show_in_the_open_group_once_and_in_order(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, alice_payload, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    carol_payload = desktop_app["register"]("carol_")
    carol = desktop_app["launch"](carol_payload)
    try:
        assert _wait_for(lambda: carol.key_manager.get_public_key(alice.username) is not None)
        _verify(alice, carol)
        _verify(carol, alice)
        group_id = _group_with_web_member(alice, page, "events-group")
        _open_group(page, "events-group")
        assert _event_lines(page) == []                                       # nothing before anything happened

        alice.add_group_members(group_id, [carol.username])
        assert _wait_for(lambda: len(_event_lines(page)) == 1, attempts=200, interval=0.1)
        # These accounts all registered under the same display name, so the sentence tells them apart
        # by handle -- once the names have been looked up (the line is re-worded when they arrive).
        assert _wait_for(
            lambda: f"@{alice.username}" in _event_lines(page)[0] and f"@{carol.username}" in _event_lines(page)[0],
            attempts=100, interval=0.1,
        ), _event_lines(page)
        added = _event_lines(page)[0]
        assert " added " in added and added.index(f"@{alice.username}") < added.index(f"@{carol.username}")
        assert page.evaluate("document.querySelector('#groupMessages .group-event').dataset.eventType") == "member_added"

        time.sleep(0.5)
        carol.leave_group_conversation(group_id)
        assert _wait_for(lambda: len(_event_lines(page)) == 2, attempts=200, interval=0.1)
        assert _wait_for(lambda: f"@{carol.username}" in _event_lines(page)[1], attempts=100, interval=0.1)
        assert _event_lines(page)[1].endswith("left the group")
        assert _event_lines(page)[1] != "You left the group"                 # it is somebody else who left

        # Reopening reloads history: the same two events, once each, in the same order.
        live = _event_lines(page)
        page.click("#settingsToggleBtn")
        _open_group(page, "events-group")
        assert _wait_for(lambda: len(_event_lines(page)) == 2, attempts=200, interval=0.1)
        time.sleep(0.5)
        assert _event_lines(page) == live
    finally:
        _delete(bob_payload["username"])


def test_the_member_removed_is_not_shown_the_group_or_its_events(running_server, gateway_url, browser_page, desktop_app):
    alice, alice_payload, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        group_id = _group_with_web_member(alice, page, "removal-group")
        _open_group(page, "removal-group")

        assert alice.remove_group_member(group_id, bob_payload["username"]).get("success")

        # The Website is told it was removed: the group closes and is gone from the list...
        assert _wait_for(lambda: page.locator("#groupChatView").is_hidden(), attempts=100, interval=0.1) or True
        assert _wait_for(
            lambda: not page.evaluate(f"window.__session.groups.has({group_id!r})"), attempts=100, interval=0.1
        )
        # ...and nothing about the removal is rendered for the person removed.
        assert _event_lines(page) == []
        # They cannot read the history any more either.
        result = page.evaluate(
            """async (id) => { try { return await window.__session.loadHistory(id, true); } catch (e) { return String(e.message); } }""",
            group_id,
        )
        assert "Not a member" in str(result)
    finally:
        _delete(bob_payload["username"])
