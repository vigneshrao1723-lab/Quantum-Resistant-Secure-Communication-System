"""
A user can see their OWN safety number, and it is the one other people see.

Verification asks a person to read a safety number to the other side. Each
client shows the *peer's* number in a conversation, so without this a user had
no way to learn their own. Here a real Desktop session and a real Chrome
session are mutually verified, and each side's own number must equal what the
other side observed for it.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gui.account_settings_dialog import AccountSettingsDialog
from tests.test_web_messenger_layout_and_parity import (  # noqa: F401 -- fixtures reused
    _delete,
    _pair,
    browser_page,
    desktop_app,
    gateway_url,
    running_server,
    static_url,
)

_app = QApplication.instance() or QApplication([])
_KEEP_ALIVE = []


def _spaced(number):
    return " ".join(number.split())


def test_desktop_own_safety_number_is_what_the_web_user_observes(running_server, gateway_url, browser_page, desktop_app):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        own = alice.get_own_fingerprint()
        assert own and len(own.replace(" ", "")) == 64

        observed_by_web = page.evaluate("[...window.__session.peers.values()].map(p => p.fingerprint)")
        assert _spaced(own) in [_spaced(f) for f in observed_by_web]
    finally:
        _delete(bob_payload["username"])


def test_desktop_settings_has_no_standing_safety_number_panel(running_server, gateway_url, browser_page, desktop_app):
    """The number belongs to a contact's verification screen, not to a card in Settings."""
    from PySide6.QtWidgets import QLabel

    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        dialog = AccountSettingsDialog(alice)
        _KEEP_ALIVE.append(dialog)

        assert not hasattr(dialog, "own_safety_number_label")
        assert dialog.findChild(QLabel, "OwnSafetyNumber") is None
        assert not any("safety number" in label.text().lower() for label in dialog.findChildren(QLabel))
    finally:
        _delete(bob_payload["username"])


def test_desktop_verify_dialog_shows_the_own_number_only_when_asked(running_server, gateway_url, browser_page, desktop_app):
    from gui.verify_identity_dialog import VerifyIdentityDialog

    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        bob = bob_payload["username"]
        dialog = VerifyIdentityDialog(alice, bob, alice.get_peer_verification_state(bob))
        _KEEP_ALIVE.append(dialog)
        dialog.show()

        # Hidden until the explicit action...
        assert dialog.own_fingerprint_label.isHidden()
        assert dialog.show_own_button.text() == "Show my safety number"

        dialog.show_own_button.click()

        # ...then the same number the Web user observes for this account.
        assert not dialog.own_fingerprint_label.isHidden()
        assert dialog.own_fingerprint_label.objectName() == "OwnSafetyNumber"
        assert dialog.own_fingerprint_label.text() == alice.get_own_fingerprint()
        observed_by_web = page.evaluate("[...window.__session.peers.values()].map(p => p.fingerprint)")
        assert _spaced(dialog.own_fingerprint_label.text()) in [_spaced(f) for f in observed_by_web]
        assert dialog.show_own_button.text() == "Hide my safety number"

        dialog.show_own_button.click()
        assert dialog.own_fingerprint_label.isHidden()
    finally:
        _delete(bob_payload["username"])


def test_web_shows_the_own_safety_number_in_the_verification_details_not_in_settings(
    running_server, gateway_url, browser_page, desktop_app
):
    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        # Settings has no standing safety-number panel any more.
        page.click("#settingsToggleBtn")
        assert page.locator("#settingsView #ownSafetyNumber").count() == 0

        # It is next to the comparison it is for, behind an explicit action.
        page.fill("#peerUsername", alice.username)
        page.press("#peerUsername", "Enter")
        page.wait_for_selector("#chatView:not([hidden])")
        assert not page.locator("#ownSafetyNumber").is_visible()
        page.click("#reverifyBtn")
        page.click("#showOwnNumberBtn")
        page.wait_for_function(
            "document.getElementById('ownSafetyNumber').textContent.trim().split(/\\s+/).length === 16",
            timeout=10000,
        )

        shown = page.inner_text("#ownSafetyNumber")
        assert _spaced(shown) == _spaced(alice.get_peer_fingerprint_for_verification(bob_payload["username"]))
    finally:
        _delete(bob_payload["username"])


def test_no_identity_yet_means_no_number_rather_than_an_invented_one():
    from client.session import ClientSession

    session = ClientSession()
    session.key_manager = None

    assert session.get_own_fingerprint() is None


def test_the_settings_dialog_never_needs_more_height_than_a_small_screen_has(running_server, gateway_url, browser_page, desktop_app):
    """Its sections scroll and Logout / Close stay on screen: the dialog used to be taller than the
    default window, pushing Logout and Close off the bottom of a small display."""
    from PySide6.QtWidgets import QScrollArea

    alice, _ap, bob_payload, page = _pair(desktop_app, browser_page, gateway_url)
    try:
        dialog = AccountSettingsDialog(alice)
        _KEEP_ALIVE.append(dialog)
        dialog.show()

        assert dialog.findChild(QScrollArea, "SettingsScroll") is not None
        assert dialog.height() <= 780
        # The pinned buttons sit inside the dialog, below the scrolling sections.
        for button in (dialog.logout_button,):
            assert dialog.rect().contains(button.mapTo(dialog, button.rect().bottomLeft()))
    finally:
        _delete(bob_payload["username"])
