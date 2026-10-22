"""Capture genuine screenshots of the running Desktop executable and the Website.

    python scripts/capture_screenshots.py [--out screenshots/preliminary]

Starts the isolated acceptance deployment (database ``qrscs_accept``, server, gateway, static web
server), creates synthetic accounts through the real registration forms, walks both applications
through their screens and saves what is actually on screen:

* Website: Playwright screenshots of the real page (desktop width, a phone width, dark theme).
* Desktop: the pixels of the running ``QRSCS-Desktop.exe`` window (not a re-render).

Accounts and passwords are random and synthetic; password fields are masked by the applications and
no credential is ever typed into a visible, unmasked field. A step that cannot be reached is recorded
in ``capture_report.json`` rather than skipped silently.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import uuid
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.acceptance import desktop_driver as dd  # noqa: E402
from tests.acceptance.conftest import new_identity  # noqa: E402
from tests.acceptance.parties import WebParty, converse, verify_pair  # noqa: E402
from tests.acceptance.stack import AcceptanceStack  # noqa: E402
from tests.acceptance.web_driver import WebUser, wait_until  # noqa: E402

EXE = Path(os.environ.get("QRSCS_DESKTOP_EXE") or (ROOT / "dist" / "desktop" / "QRSCS-Desktop" / "QRSCS-Desktop.exe"))


def _png(width=320, height=200):
    """A small real PNG (a blue-violet gradient) to send as an image attachment."""
    rows = b"".join(
        b"\x00" + b"".join(bytes([60 + (x * 120) // width, 80 + (y * 100) // height, 220]) for x in range(width))
        for y in range(height)
    )

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


class Capture:
    def __init__(self, out: Path):
        self.out = out
        self.report: list[dict] = []
        (out / "website").mkdir(parents=True, exist_ok=True)
        (out / "desktop").mkdir(parents=True, exist_ok=True)

    def step(self, group: str, name: str, action):
        path = self.out / group / f"{name}.png"
        try:
            action(path)
            self.report.append({"shot": f"{group}/{name}.png", "ok": True})
            print(f"  ok   {group}/{name}")
        except Exception as error:  # recorded, never silent
            self.report.append({"shot": f"{group}/{name}.png", "ok": False, "error": f"{type(error).__name__}: {str(error)[:160]}"})
            print(f"  FAIL {group}/{name}: {error}")

    def save(self):
        (self.out / "capture_report.json").write_text(json.dumps(self.report, indent=2), encoding="utf-8")


def website_shots(cap: Capture, stack, browser, group_name: str, image: Path):
    def shot(user):
        return lambda path: user.page.screenshot(path=str(path))

    # -- login / register / error (fresh page, not signed in) --
    a_ident, b_ident, c_ident = (new_identity(p) for p in ("shotA", "shotB", "shotC"))
    a = WebUser(browser, stack, a_ident["username"], a_ident["phone"], a_ident["password"])
    b = WebUser(browser, stack, b_ident["username"], b_ident["phone"], b_ident["password"])
    c = WebUser(browser, stack, c_ident["username"], c_ident["phone"], c_ident["password"])
    a.open()
    cap.step("website", "01_login", shot(a))
    a.page.click("#toggleModeBtn")
    cap.step("website", "02_register_form", shot(a))
    a.page.click("#toggleModeBtn")
    a.page.fill("#phoneNumber", a.phone)
    a.page.fill("#password", a.password + "x")
    a.page.click("#connectBtn")
    wait_until(lambda: "is-error" in (a.page.get_attribute("#authStatus", "class") or ""), 20, what="login error")
    cap.step("website", "03_login_error", shot(a))

    for user in (a, b, c):
        user.register()
        user.login()
    cap.step("website", "04_signed_in_empty", shot(a))

    pa, pb, pc = WebParty(a), WebParty(b), WebParty(c)
    a.open_chat(b.username)
    b.open_chat(a.username)
    cap.step("website", "05_unverified_contact_security_bar", shot(a))
    verify_pair(pa, pb)
    a.establish_key()
    converse(pa, pb, "hello")
    a.send("Here is the plan for tomorrow")
    b.wait_for_message("Here is the plan for tomorrow")
    b.reply_to("Here is the plan for tomorrow", "Sounds good, see you then")
    a.wait_for_message("Sounds good, see you then")
    a.page.set_input_files("#attachmentInput", str(image))
    a.page.click("#sendAttachmentBtn")
    wait_until(lambda: b.page.locator("#messages img.msg-image").count() >= 1, 30, what="the image")
    cap.step("website", "06_conversation_verified", shot(a))
    cap.step("website", "07_conversation_recipient_view", shot(b))

    a.page.click(".bubble-text:has-text('Here is the plan')", button="right")
    cap.step("website", "08_message_actions_menu", shot(a))
    a.page.keyboard.press("Escape")
    a.page.click("body", position={"x": 5, "y": 5})

    # Chat settings (the header gear), then the verification details with the user's own number on request.
    a.page.mouse.move(700, 700)  # off the message, so no hover toolbar is drawn over the menu
    a.page.click("#chatSettingsBtn")
    a.page.wait_for_timeout(600)  # the menu fades in
    cap.step("website", "08b_chat_settings_menu", shot(a))
    a.page.keyboard.press("Escape")

    def own_number_shot(path):
        if a.page.is_visible("#reverifyBtn"):  # hidden while the details are already open
            a.page.click("#reverifyBtn")
        a.page.click("#showOwnNumberBtn")
        wait_until(lambda: len(a.page.inner_text("#ownSafetyNumber").split()) == 16, 15, what="own safety number")
        a.page.screenshot(path=str(path))

    cap.step("website", "08c_verification_details_own_number", own_number_shot)

    a.chat_tool("galleryBtn")
    wait_until(lambda: a.page.evaluate("!!document.querySelector('.gallery-thumb')"), 20, what="gallery")
    cap.step("website", "09_media_gallery", shot(a))
    a.page.keyboard.press("Escape")

    # -- group --
    verify_pair(pa, pc)
    a.create_group(group_name, [b.username, c.username])
    cap.step("website", "10a_group_invitations_waiting", shot(a))
    # Each person joins by approving the invitation in their own Inbox.
    b.approve_invitation(group_name)
    c.approve_invitation(group_name)
    b.open_group(group_name)
    a.open_group(group_name)
    a.send_group("Welcome to the group")
    b.wait_for_group_message("Welcome to the group")
    cap.step("website", "10_group_conversation", shot(a))
    a.group_member_names(group_name)
    cap.step("website", "11_group_info_and_management", shot(a))

    # -- inbox: a verification request --
    c.open_chat(b.username)
    b.open_chat(c.username)
    c.page.click("#requestVerificationBtn")
    b.page.click('.tab-btn[data-tab="inbox"]')
    wait_until(lambda: c.username in b.page.inner_text("#inboxList"), 20, what="inbox item")
    cap.step("website", "12_inbox_verification_request", shot(b))

    # -- settings (profile, linked devices; the safety number is in a contact's verification details) --
    a.page.click("#settingsToggleBtn")
    a.page.wait_for_timeout(6000)  # let earlier notifications (toasts) disappear
    cap.step("website", "13_settings_profile_and_account", shot(a))
    a.page.evaluate("document.querySelector('.panel-header:has(+ .card #myDeviceId)')?.scrollIntoView()")
    a.page.click("#enrollDeviceBtn")
    wait_until(lambda: "(" in a.page.inner_text("#myDeviceId"), 15, what="device enrolled")
    a.page.click("#listDevicesBtn")
    cap.step("website", "14_settings_linked_devices", lambda path: a.page.locator("#deviceList").scroll_into_view_if_needed() or a.page.screenshot(path=str(path)))

    # -- dark theme and a phone-width layout --
    a.page.evaluate("document.documentElement.dataset.theme = 'dark'")
    a.page.click("#chatBackBtn") if a.page.is_visible("#chatBackBtn") else None
    cap.step("website", "15_dark_theme_settings", shot(a))
    a.page.evaluate("document.documentElement.dataset.theme = 'light'")

    phone = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    page = phone.new_page()
    page.goto(stack.web_url)
    page.wait_for_selector("html[data-app-ready]", state="attached")
    # (the gateway address is a collapsed "Connection settings" field; the input still holds the value)
    page.evaluate("(u) => { document.getElementById('gatewayUrl').value = u; }", stack.gateway_url)
    cap.step("website", "16_phone_login", lambda path: page.screenshot(path=str(path)))
    page.fill("#phoneNumber", b.phone)
    page.fill("#password", b.password)
    page.click("#connectBtn")
    wait_until(lambda: page.is_visible("#screen-app"), 30, what="phone sign-in")
    wait_until(lambda: page.locator("#chatList .row-card").count() > 0, 30, what="chat list")
    cap.step("website", "17_phone_chat_list", lambda path: page.screenshot(path=str(path)))
    page.click("#chatList .row-card >> nth=0")
    cap.step("website", "18_phone_conversation", lambda path: page.screenshot(path=str(path)))
    phone.close()

    for user in (a, b, c):
        user.close()


def desktop_shots(cap: Capture, stack, uia, other_username, other_phone):
    key_store = Path(tempfile.mkdtemp(prefix="qrscs_ks_"))
    ident = new_identity("shotD")
    app = dd.DesktopApp([str(EXE)], stack.client_env(key_store), uia)
    app.username, app.phone, app.password = ident["username"], ident["phone"], ident["password"]
    def shot(path):
        app.screenshot(path)

    try:
        time.sleep(2)
        cap.step("desktop", "01_login", shot)
        app.click(id="AuthModeToggle")
        app.wait_for(lambda: app.get(id="UsernameInput"), what="register form")
        cap.step("desktop", "02_register_form", shot)
        app.click(id="AuthModeToggle")
        app.set_text(app.phone, id="PhoneInput")
        app.set_text(app.password + "x", id="PasswordInput")
        app.click(id="AuthPrimaryAction")
        app.wait_for(lambda: any("Invalid phone number or password" in e["name"] for e in app.tree()), what="login error")
        cap.step("desktop", "03_login_error", shot)

        dd.register(app, app.username, app.phone, app.password)
        dd.login(app, app.phone, app.password)
        cap.step("desktop", "04_main_window_empty", shot)

        app.click(name="New chat")
        app.wait_for(lambda: app.get(id="FindUserDialog.QLineEdit"), what="find user")
        app.set_text(other_phone, id="FindUserDialog.QLineEdit")
        app.click(id="FindUserDialog", name="Search")
        app.wait_for(lambda: app.get(id="FindUserDialog", name="Open Chat")["enabled"], what="search result")
        cap.step("desktop", "05_find_user_dialog", shot)
        app.click(id="FindUserDialog", name="Open Chat")
        app.wait_for(lambda: app.get(id="ChatHeader.HeaderActionButton", name="Verify Identity"), what="chat")
        cap.step("desktop", "06_chat_unverified_contact", shot)

        app.click(name="Verify Identity")
        app.wait_for(lambda: app.get(id="VerifyIdentityDialog.Fingerprint"), what="verify dialog")
        cap.step("desktop", "07_verify_identity_dialog", shot)
        return app, key_store
    except Exception:
        app.stop()
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "screenshots" / "preliminary")
    args = parser.parse_args(argv)
    if not EXE.is_file():
        print(f"build the executable first: {EXE}", file=sys.stderr)
        return 2

    import acceptance_db
    from playwright.sync_api import sync_playwright

    out = args.out.resolve()
    cap = Capture(out)
    work = Path(tempfile.mkdtemp(prefix="qrscs_shots_"))
    image = work / "photo.png"
    image.write_bytes(_png())
    uia = dd.UiaAgent()
    acceptance_db.create()
    with AcceptanceStack(work) as stack, sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome", headless=True)
        group = f"Project {uuid.uuid4().hex[:4]}"
        try:
            print("Website")
            website_shots(cap, stack, browser, group, image)

            print("Desktop")
            # The Desktop user chats with a fresh Website user so every Desktop screen shows real traffic.
            peer_ident = new_identity("shotP")
            peer = WebUser(browser, stack, peer_ident["username"], peer_ident["phone"], peer_ident["password"])
            peer.register()
            peer.login()
            try:
                result = desktop_shots(cap, stack, uia, peer.phone, peer.phone)
                app, key_store = result
                try:
                    def shot(path):
                        app.screenshot(path)

                    # The Verify Identity dialog is still open from desktop_shots(): confirm there, then
                    # the Website user confirms the Desktop user, and messages are exchanged.
                    peer.open_chat(app.username)
                    dd.confirm_fingerprint_match(app)
                    peer.confirm_match()
                    peer.establish_key()
                    dd.send_message(app, "Hello from the desktop app")
                    peer.wait_for_message("Hello from the desktop app")
                    peer.send("Hello back from the website")
                    app.wait_for(lambda: "Hello back from the website" in dd.conversation_text(app), what="reply on desktop")
                    peer.send("Here is a second message with a bit more text so the bubble wraps nicely")
                    app.wait_for(lambda: "second message" in dd.conversation_text(app), what="second reply")
                    cap.step("desktop", "08_conversation_verified", shot)

                    app.click(id="ChatHeader.IconButton", name="Chat settings")
                    time.sleep(2)
                    cap.step("desktop", "08b_chat_settings", shot)
                    app.keys("{ESC}")
                    time.sleep(0.5)

                    dd.open_settings(app)
                    cap.step("desktop", "09_settings_profile_and_account", shot)
                    dd.close_settings(app)

                    app.click(id="NavRail.RailButton", name="Devices")
                    time.sleep(2)
                    cap.step("desktop", "10_devices_dialog", shot)
                    app.keys("{ESC}")
                    time.sleep(0.5)

                    app.click(id="NavRail.RailButton", name="Inbox")
                    time.sleep(2)
                    cap.step("desktop", "11_inbox_dialog", shot)
                    app.keys("{ESC}")
                    time.sleep(0.5)

                    # A group the Website user creates with the Desktop user as a member.
                    group_name = f"Desktop group {uuid.uuid4().hex[:4]}"
                    peer.create_group(group_name, [app.username])
                    dd.approve_first_invitation(app)
                    dd.open_conversation(app, group_name)
                    peer.open_group(group_name)
                    peer.send_group("Welcome, desktop member")
                    app.wait_for(lambda: "Welcome, desktop member" in dd.conversation_text(app), what="group message")
                    cap.step("desktop", "12_group_conversation", shot)
                    app.click(name="Group Info")
                    time.sleep(2)
                    cap.step("desktop", "13_group_info_dialog", shot)
                    app.keys("{ESC}")
                    time.sleep(0.5)
                finally:
                    app.stop()
                    shutil.rmtree(key_store, ignore_errors=True)
            finally:
                peer.close()
        finally:
            browser.close()
    uia.close()
    cap.save()
    failed = [r for r in cap.report if not r["ok"]]
    print(f"{len(cap.report) - len(failed)} captured, {len(failed)} failed -> {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
