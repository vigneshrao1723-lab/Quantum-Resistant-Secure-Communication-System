"""
Website: Chat settings menu, the voice/video recorder modal, and the collapsed gateway setting.

Real Chrome against the real page, gateway, server and a real Desktop peer.
"""

import pytest

from tests.test_web_browser_e2e import (  # noqa: F401 -- fixtures reused, not re-implemented
    _connect_browser,
    _delete,
    _register,
    _wait_for,
    browser_page,
    chat_tool,
    desktop_app,
    gateway_url,
    running_server,
    set_gateway,
    static_url,
)
from tests.test_web_messenger_layout_and_parity import _group_with_web_member, _no_horizontal_overflow, _pair
from tests.test_web_phase19_24_lifecycle_ui import _establish_key_in_browser, _record_and_send


def _open_chat(page, peer):
    page.fill("#peerUsername", peer)
    page.press("#peerUsername", "Enter")
    page.wait_for_selector("#chatView:not([hidden])")


# ====================================================================== Chat settings menu


def test_the_chat_header_has_one_settings_icon_and_the_tools_live_in_its_menu(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_chat(page, alice.username)

        # Header: the contact, their verification status, and ONE icon button -- not a row of tools.
        header_buttons = page.locator("#chatView .chat-header-actions button:visible")
        assert header_buttons.count() == 1
        assert page.get_attribute("#chatSettingsBtn", "aria-label") == "Chat settings"
        for tool in ("searchBtn", "pinnedBtn", "galleryBtn", "wallpaperBtn", "peerProfileBtn", "markReadBtn", "loadHistoryBtn"):
            assert not page.locator(f"#{tool}").is_visible(), tool
        assert page.locator("#peerVerifiedBadge").is_visible()          # status is never hidden away

        page.click("#chatSettingsBtn")
        labels = [t.strip() for t in page.locator(".bubble-context-menu button").all_inner_texts()]
        assert labels == [
            "Contact info", "Search in conversation", "Pinned messages", "Media gallery",
            "Chat wallpaper", "Mark as read", "Load history", "Mute, archive or block…",
        ]
        page.keyboard.press("Escape")
        assert page.locator(".bubble-context-menu").count() == 0
    finally:
        _delete(bob_payload["username"])


def test_each_chat_tool_runs_from_the_menu(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_chat(page, alice.username)

        chat_tool(page, "searchBtn")
        assert page.locator("#searchBar").is_visible()
        page.click("#searchCloseBtn")

        chat_tool(page, "peerProfileBtn")
        page.wait_for_selector(".profile-card")
        assert alice.username in page.inner_text(".profile-card")
        page.keyboard.press("Escape")

        chat_tool(page, "wallpaperBtn")                 # opens its own picker, near the settings button
        picker = page.locator(".bubble-context-menu")
        assert picker.count() == 1 and "Lavender" in picker.inner_text()
        box, gear = picker.bounding_box(), page.locator("#chatSettingsBtn").bounding_box()
        assert abs(box["y"] - (gear["y"] + gear["height"])) < 60       # anchored beside the button, not a corner
        picker.locator("button", has_text="Mint").click()
        assert "wallpaper-mint" in page.get_attribute("#messages", "class")

        chat_tool(page, "galleryBtn")
        page.wait_for_selector(".gallery-list, .gallery-empty, .lightbox, .bubble-popup", timeout=5000)
        page.keyboard.press("Escape")

        # Mute / archive / block are reachable from the same menu.
        page.click("#chatSettingsBtn")
        page.click('.bubble-context-menu [data-tool="conversationOptions"]')
        options = [t.strip() for t in page.locator(".bubble-context-menu button").all_inner_texts()]
        assert any(o.startswith("Mute") for o in options) and "Archive" in options and "Block" in options
    finally:
        _delete(bob_payload["username"])


def test_the_chat_settings_menu_is_keyboard_operable(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_chat(page, alice.username)

        page.focus("#chatSettingsBtn")
        page.keyboard.press("Enter")
        assert page.evaluate("document.activeElement && document.activeElement.dataset.tool") == "peerProfileBtn"
        page.keyboard.press("ArrowDown")
        assert page.evaluate("document.activeElement.dataset.tool") == "searchBtn"
        page.keyboard.press("Enter")                    # runs the focused tool
        assert page.locator("#searchBar").is_visible()
        page.click("#searchCloseBtn")

        page.focus("#chatSettingsBtn")
        page.keyboard.press("Enter")
        page.keyboard.press("Escape")
        assert page.locator(".bubble-context-menu").count() == 0
        assert page.evaluate("document.activeElement.id") == "chatSettingsBtn"   # focus returns
    finally:
        _delete(bob_payload["username"])


def test_a_groups_header_keeps_members_visible_and_moves_the_rest_into_chat_settings(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _group_with_web_member(alice, page, "menu-group")
        page.click('.tab-btn[data-tab="groups"]')
        page.click('.row-card:has-text("menu-group")')
        page.wait_for_selector("#groupChatView:not([hidden])")

        assert page.locator("#groupInfoBtn").is_visible()                # the members stay one click away
        assert page.locator("#groupInfoBtn").inner_text().strip() == "Members"
        assert page.locator("#groupChatView .chat-header-actions button:visible").count() == 2
        for tool in ("groupSearchBtn", "groupPinnedBtn", "groupGalleryBtn", "groupWallpaperBtn", "loadGroupHistoryBtn"):
            assert not page.locator(f"#{tool}").is_visible(), tool

        page.click("#groupSettingsBtn")
        labels = [t.strip() for t in page.locator(".bubble-context-menu button").all_inner_texts()]
        assert labels == [
            "Search in conversation", "Pinned messages", "Media gallery", "Chat wallpaper",
            "Load history", "Mute or archive…",
        ]
        assert "Contact info" not in labels
        page.keyboard.press("Escape")

        chat_tool(page, "groupSearchBtn")
        assert page.locator("#groupSearchBar").is_visible()
    finally:
        _delete(bob_payload["username"])


def test_the_header_fits_a_phone_with_the_settings_icon(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_chat(page, alice.username)                 # (the search box is not on screen once a chat is open on a phone)
        page.set_viewport_size({"width": 390, "height": 800})
        page.wait_for_timeout(250)
        assert page.locator("#chatSettingsBtn").is_visible()
        box = page.locator("#chatSettingsBtn").bounding_box()
        assert box["x"] >= 0 and box["x"] + box["width"] <= 391 and box["width"] >= 32
        assert _no_horizontal_overflow(page)
        page.click("#chatSettingsBtn")
        menu = page.locator(".bubble-context-menu").bounding_box()
        assert menu["x"] >= 0 and menu["x"] + menu["width"] <= 391       # never spills off the screen
    finally:
        _delete(bob_payload["username"])


# ====================================================================== Recorder modal


RECORD = ".media-recorder-card > [data-role=record]"


def _open_recorder(page, peer, mode="voice", prepare=True):
    if prepare:
        _open_chat(page, peer)
        _establish_key_in_browser(page, peer)
    page.click("#attachBtn")
    page.click(f".bubble-context-menu >> text={'Voice' if mode == 'voice' else 'Video'} Message")
    page.wait_for_selector(".media-recorder-card")


def test_the_voice_recorder_walks_through_record_preview_record_again_and_send(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        received = []
        alice.payload_message_received.connect(
            lambda key, sender, payload_type, data, metadata: received.append((payload_type, bytes(data)))
        )
        _open_recorder(page, alice.username)
        record = RECORD

        # Idle: clean, labelled, Send disabled, a timer at zero, no preview yet.
        assert page.get_attribute(".media-recorder-card", "role") == "dialog"
        assert page.inner_text(".media-recorder-card .confirm-modal-title") == "Voice message"
        assert page.inner_text(".media-recorder-timer") == "0:00"
        assert page.locator(".media-recorder-actions .btn-primary").is_disabled()
        assert page.locator("audio.media-recorder-preview").count() == 0
        assert page.evaluate("document.activeElement.closest('.media-recorder-card') !== null")   # focus is in the dialog

        # Recording: the timer runs, the button becomes Stop, Send stays off.
        page.click(record)
        assert page.get_attribute(".media-recorder-card", "data-state") == "recording"
        assert "Stop" in page.inner_text(record)
        assert _wait_for(lambda: page.inner_text(".media-recorder-timer") != "0:00", attempts=60, interval=0.1)
        assert page.locator(".media-recorder-actions .btn-primary").is_disabled()
        page.wait_for_timeout(600)
        page.click(record)

        # Recorded: a playable preview of the real recording, Record again, Send enabled.
        assert _wait_for(lambda: page.get_attribute(".media-recorder-card", "data-state") == "recorded")
        assert page.locator("audio.media-recorder-preview").count() == 1
        first_take = page.get_attribute("audio.media-recorder-preview", "src")
        assert page.evaluate("document.querySelector('audio.media-recorder-preview').controls")
        assert "Record again" in page.inner_text(record)
        assert page.locator(".media-recorder-actions .btn-primary").is_enabled()

        # Record again discards the first take and starts over from zero.
        page.click(record)
        assert page.get_attribute(".media-recorder-card", "data-state") == "recording"
        assert page.locator("audio.media-recorder-preview").count() == 0
        assert page.locator(".media-recorder-actions .btn-primary").is_disabled()
        page.wait_for_timeout(700)
        page.click(record)
        assert _wait_for(lambda: page.get_attribute(".media-recorder-card", "data-state") == "recorded")
        assert page.get_attribute("audio.media-recorder-preview", "src") != first_take

        # Send: the modal closes, the clip is in the transcript and reaches the Desktop peer encrypted.
        page.click(".media-recorder-actions .btn-primary")
        assert _wait_for(lambda: page.locator(".media-recorder-card").count() == 0, attempts=100, interval=0.1)
        assert page.locator("#messages audio.bubble-media").count() == 1
        assert _wait_for(lambda: len(received) == 1, attempts=200, interval=0.1)
        assert received[0][0] == "voice" and len(received[0][1]) > 0
    finally:
        _delete(bob_payload["username"])


def test_cancelling_or_pressing_escape_discards_the_recording_and_releases_the_microphone(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        received = []
        alice.payload_message_received.connect(lambda *args: received.append(args))
        page.evaluate("""() => {
          window.__tracks = [];
          const original = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
          navigator.mediaDevices.getUserMedia = async (c) => { const s = await original(c); window.__tracks.push(...s.getTracks()); return s; };
        }""")

        for index, how in enumerate(("cancel", "escape")):
            _open_recorder(page, alice.username, prepare=index == 0)
            page.click(RECORD)
            page.wait_for_timeout(500)
            if how == "cancel":
                page.click(".media-recorder-actions .btn-ghost")
            else:
                page.keyboard.press("Escape")
            assert _wait_for(lambda: page.locator(".media-recorder-card").count() == 0, attempts=60, interval=0.1), how
            assert page.evaluate("window.__tracks.every(t => t.readyState === 'ended')"), how
            assert page.locator("#messages audio.bubble-media").count() == 0, how

        page.wait_for_timeout(300)
        assert received == []                                            # nothing was ever sent
    finally:
        _delete(bob_payload["username"])


@pytest.mark.parametrize("error_name, expected", [
    ("NotAllowedError", "blocked"),
    ("NotFoundError", "No microphone was found"),
    ("NotReadableError", "being used by another app"),
])
def test_a_microphone_problem_is_explained_and_no_recorder_opens(
    running_server, gateway_url, browser_page, desktop_app, error_name, expected
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_chat(page, alice.username)
        _establish_key_in_browser(page, alice.username)
        page.evaluate(
            """(name) => { navigator.mediaDevices.getUserMedia = () => Promise.reject(new DOMException('no', name)); }""",
            error_name,
        )

        page.click("#attachBtn")
        page.click(".bubble-context-menu >> text=Voice Message")

        assert _wait_for(lambda: expected in page.inner_text("#toastRegion"), attempts=60, interval=0.1)
        assert page.locator(".media-recorder-card").count() == 0
    finally:
        _delete(bob_payload["username"])


def test_the_video_recorder_shows_a_live_preview_then_the_recording(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_recorder(page, alice.username, "video")
        assert page.inner_text(".media-recorder-card .confirm-modal-title") == "Video message"
        assert page.locator("video.media-recorder-preview").count() == 1
        assert page.evaluate("!!document.querySelector('video.media-recorder-preview').srcObject")   # live camera

        record = RECORD
        page.click(record)
        page.wait_for_timeout(1200)
        page.click(record)
        assert _wait_for(lambda: page.get_attribute(".media-recorder-card", "data-state") == "recorded")
        assert page.evaluate("!document.querySelector('video.media-recorder-preview').srcObject")    # now the recording
        assert page.evaluate("document.querySelector('video.media-recorder-preview').controls")
        assert page.locator(".media-recorder-actions .btn-primary").is_enabled()
    finally:
        _delete(bob_payload["username"])


def test_the_recorder_fits_a_phone(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        _open_chat(page, alice.username)
        _establish_key_in_browser(page, alice.username)
        page.set_viewport_size({"width": 360, "height": 640})
        page.wait_for_timeout(250)
        _open_recorder(page, alice.username, prepare=False)
        card = page.locator(".media-recorder-card").bounding_box()
        assert card["x"] >= 0 and card["x"] + card["width"] <= 361 and card["y"] >= 0 and card["y"] + card["height"] <= 641
        for selector in (RECORD, ".media-recorder-actions .btn-ghost", ".media-recorder-actions .btn-primary"):
            box = page.locator(selector).bounding_box()
            assert box["height"] >= 34, selector
        assert _no_horizontal_overflow(page)
    finally:
        _delete(bob_payload["username"])


# ====================================================================== Gateway address


def test_the_gateway_address_is_a_collapsed_setting_that_still_works(running_server, gateway_url, browser_page):
    page = browser_page["page"]
    bob = _register("gw_")
    try:
        # Collapsed by default: a person signing in sees phone, password and the buttons -- not a URL.
        assert not page.locator("#gatewayUrl").is_visible()
        assert page.locator("#connectionSettingsSummary").is_visible()
        assert page.locator("#connectionSettings").get_attribute("open") is None

        # Yet it is there when needed: open the disclosure, enter the address, sign in.
        page.click("#connectionSettingsSummary")
        assert page.locator("#gatewayUrl").is_visible()
        page.fill("#gatewayUrl", gateway_url)
        page.fill("#phoneNumber", bob["phone_number"])
        page.fill("#password", "Str0ng!Passw0rd")
        page.click("#connectBtn")
        assert _wait_for(lambda: "Ready." in page.inner_text("#log"), attempts=200, interval=0.1)
    finally:
        _delete(bob["username"])


def test_the_gateway_address_can_be_given_in_the_page_address(running_server, gateway_url, browser_page):
    page = browser_page["page"]
    base = page.url.split("?")[0]

    page.goto(f"{base}?debug=1&gateway=ws://gateway.example:9999")
    page.wait_for_selector("html[data-app-ready]", state="attached")
    assert page.input_value("#gatewayUrl") == "ws://gateway.example:9999"

    # Anything that is not a WebSocket address is ignored.
    page.goto(f"{base}?debug=1&gateway=javascript:alert(1)")
    page.wait_for_selector("html[data-app-ready]", state="attached")
    assert page.input_value("#gatewayUrl").startswith("ws")
