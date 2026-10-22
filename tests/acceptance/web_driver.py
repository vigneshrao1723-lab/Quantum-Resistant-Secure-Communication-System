"""Drive the real Website through Playwright (system Chrome).

Every ``WebUser`` has its own browser *context*, i.e. its own storage, cookies
and identity keys -- a separate authenticated session/device, never a shared one.
Registration and login go through the actual form; nothing is inserted into the
database directly.
"""

from __future__ import annotations

import re
import time

from tests.acceptance import evidence

LOG_READY = "Ready."

_GROUP_NAMES_JS = "Array.from(window.__session.groups.values()).map(g => g.name)"


def wait_until(predicate, timeout: float = 20.0, interval: float = 0.1, what: str = "condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:  # page may be mid-navigation / element not there yet
            last = error
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what}" + (f" (last error: {last})" if last else ""))


def safety_digits(text: str) -> str:
    """The hex groups of a displayed safety number (ignores the surrounding words/usernames)."""
    groups = re.findall(r"\b[0-9A-Fa-f]{4}\b", text.split("]", 1)[-1])
    return "".join(groups).upper()


class WebUser:
    def __init__(self, browser, stack, username: str, phone: str, password: str):
        self.stack = stack
        self.username, self.phone, self.password = username, phone, password
        self.console_errors: list[str] = []
        self.page_errors: list[str] = []
        self.context = browser.new_context(viewport={"width": 1280, "height": 800})
        self.page = self.context.new_page()
        self.page.route("**/favicon.ico", lambda r: r.fulfill(status=204, body=""))
        self.page.on("console", lambda m: self.console_errors.append(m.text) if m.type == "error" else None)
        self.page.on("pageerror", lambda e: self.page_errors.append(str(e)))
        # WebSocket trace for diagnosing lost-packet failures: timing and sizes only, never payloads
        # (registration/login frames carry passwords).
        self.ws_events: list[str] = []
        self._t0 = time.monotonic()
        self.page.on("websocket", self._trace_websocket)

    # -- diagnostics ------------------------------------------------------
    def _stamp(self, text: str):
        self.ws_events.append(f"{time.monotonic() - self._t0:7.2f}s {text}")

    def _trace_websocket(self, ws):
        self._stamp(f"ws opened {ws.url}")
        ws.on("framesent", lambda payload: self._stamp(f"ws frame sent ({len(payload)} bytes)"))
        ws.on("framereceived", lambda payload: self._stamp(f"ws frame received ({len(payload)} bytes)"))
        ws.on("close", lambda _ws: self._stamp("ws closed"))
        ws.on("socketerror", lambda err: self._stamp(f"ws error {err}"))

    def diagnostics(self) -> str:
        try:
            status = self.page.inner_text("#authStatus")
        except Exception:
            status = "<unreadable>"
        return f"authStatus={status!r}; websocket trace: " + " | ".join(self.ws_events[-12:])

    # -- accounts ---------------------------------------------------------
    def open(self):
        self.page.goto(self.stack.web_url)
        self.page.wait_for_selector("html[data-app-ready]", state="attached", timeout=15000)
        # The gateway address is a collapsed "Connection settings" field; the input still holds the
        # value the Connect button reads.
        self.page.evaluate("(u) => { document.getElementById('gatewayUrl').value = u; }", self.stack.gateway_url)

    def register(self):
        self.open()
        self.page.click("#toggleModeBtn")
        self.page.fill("#regUsername", self.username)
        self.page.fill("#phoneNumber", self.phone)
        self.page.fill("#password", self.password)
        self.page.fill("#regConfirmPassword", self.password)
        self._stamp("click Register")
        self.page.click("#connectBtn")
        try:
            wait_until(lambda: "Account created" in self.page.inner_text("#authStatus"), 20, what="registration")
        except AssertionError as error:
            raise AssertionError(f"{error}; {self.diagnostics()}") from None

    def login(self):
        if not self.page.url.startswith("http"):
            self.open()
        self.page.fill("#phoneNumber", self.phone)
        self.page.fill("#password", self.password)
        self.page.click("#connectBtn")
        wait_until(lambda: "Connected and authenticated as" in self.page.inner_text("#log"), 30, what="login")
        wait_until(lambda: LOG_READY in self.page.inner_text("#log"), 30, what="session ready")

    def logout(self):
        self.page.click("#logoutBtn")

    # -- identity ---------------------------------------------------------
    def own_fingerprint(self) -> str:
        """This account's own safety number, computed with the app's own code.

        The value a person would read out to the other side (shown, on request, in a contact's
        verification details).
        """
        return self.page.evaluate(
            """async () => {
                const C = await import('./crypto.js');
                const s = window.__session;
                return C.fingerprintCombinedIdentity(C.bytesToBase64(s.kemKeypair.publicKey), s.signingKeypair.publicKey);
            }"""
        )

    def safety_number(self) -> str:
        return self.page.inner_text("#fingerprintDisplay")

    # -- direct messaging -------------------------------------------------
    def chat_tool(self, tool_id: str):
        """Run a chat tool from the Chat settings menu (as a person does)."""
        self.page.click("#groupSettingsBtn" if tool_id.startswith("group") else "#chatSettingsBtn")
        self.page.click(f'.bubble-context-menu [data-tool="{tool_id}"]')

    def open_chat(self, peer: str):
        self.page.fill("#peerUsername", peer)
        self.page.press("#peerUsername", "Enter")
        wait_until(lambda: peer in self.page.inner_text("#fingerprintDisplay"), 30, what=f"safety number for {peer}")

    def confirm_match(self):
        self.page.click("#confirmVerifiedBtn")
        wait_until(lambda: "marked VERIFIED" in self.page.inner_text("#log"), 20, what="verification")

    def establish_key(self):
        # The button is hidden once the conversation already has a key (e.g. after a reconnect); a
        # person has nothing to press then, so neither does the driver.
        if self.page.is_visible("#establishKeyBtn"):
            self.page.click("#establishKeyBtn")
            wait_until(lambda: "Session key established" in self.page.inner_text("#log"), 30, what="session key")

    def send(self, text: str):
        evidence.record_plaintext(text)
        self.page.fill("#messageText", text)
        self.page.click("#sendBtn")

    def messages(self) -> str:
        return self.page.inner_text("#messages")

    def wait_for_message(self, text: str, timeout: float = 30.0):
        wait_until(lambda: text in self.messages(), timeout, what=f"message {text!r}")

    # -- message actions (right-click menu on a bubble) -------------------
    def message_action(self, bubble_text: str, label: str):
        self.page.click(f".bubble-text:has-text('{bubble_text}')", button="right")
        self.page.click(f".bubble-context-menu >> text={label}")

    def confirm_dialog(self, label: str):
        self.page.click(f".confirm-modal-actions >> text={label}")

    def reply_to(self, bubble_text: str, reply_text: str):
        evidence.record_plaintext(reply_text)
        self.message_action(bubble_text, "Reply")
        self.page.fill("#messageText", reply_text)
        self.page.click("#sendBtn")

    def edit_message(self, bubble_text: str, new_text: str):
        evidence.record_plaintext(new_text)
        self.message_action(bubble_text, "Edit")
        self.page.fill("#messageText", new_text)
        self.page.click("#sendBtn")

    def react_to(self, bubble_text: str):
        self.message_action(bubble_text, "React")
        self.page.click(".bubble-popup-emoji-row button >> nth=0")

    def delete_for_everyone(self, bubble_text: str):
        self.message_action(bubble_text, "Delete for everyone")
        self.confirm_dialog("Delete")

    def reaction_counts(self) -> list[str]:
        return self.page.evaluate(
            "[...document.querySelectorAll('#messages .reaction-chip .reaction-count')].map(e => e.textContent)"
        )

    def edited_texts(self) -> list[str]:
        return self.page.evaluate(
            "[...document.querySelectorAll('#messages .bubble')]"
            ".filter(b => b.querySelector('.bubble-footer .bubble-edited'))"
            ".map(b => b.querySelector('.bubble-text').textContent)"
        )

    def reply_previews(self) -> list[str]:
        return self.page.evaluate(
            "[...document.querySelectorAll('#messages .bubble-reply-preview')].map(e => e.textContent)"
        )

    # -- groups -----------------------------------------------------------
    def has_group(self, name: str) -> bool:
        return name in self.page.evaluate(_GROUP_NAMES_JS)

    def create_group(self, name: str, members: list[str]):
        self.page.click('.tab-btn[data-tab="groups"]')
        self.page.click("#openCreateGroupBtn")
        self.page.fill("#groupName", name)
        self.page.fill("#groupMembers", ", ".join(members))
        self.page.click("#createGroupBtn")
        wait_until(lambda: self.has_group(name), 30, what=f"group {name!r} to exist")

    def approve_invitation(self, group_name: str):
        """Approve the invitation to ``group_name`` in this account's own Inbox, then wait for the group.
        (A person joins a group only by approving the invitation.)"""
        self.page.click('.tab-btn[data-tab="inbox"]')
        self.page.wait_for_selector(".notif-card .notif-actions .btn-primary", timeout=40000)
        self.page.click(f'.notif-card:has-text("{group_name}") .notif-actions .btn-primary')
        wait_until(lambda: self.has_group(group_name), 40, what=f"{group_name!r} to appear after approving")

    def open_group(self, name: str):
        self.page.click('.tab-btn[data-tab="groups"]')
        wait_until(lambda: self.page.locator(f'#groupList .row-card:has-text("{name}")').count() > 0, 30,
                   what=f"group {name!r} in the list")
        self.page.click(f'#groupList .row-card:has-text("{name}")')
        self.page.wait_for_selector("#groupChatView:not([hidden])")

    def send_group(self, text: str):
        evidence.record_plaintext(text)
        self.page.fill("#groupMessageText", text)
        self.page.click("#sendGroupMessageBtn")

    def group_messages(self) -> str:
        return self.page.inner_text("#groupMessages")

    def wait_for_group_message(self, text: str, timeout: float = 30.0):
        wait_until(lambda: text in self.group_messages(), timeout, what=f"group message {text!r}")

    def group_member_names(self, name: str) -> str:
        """Open the group's info panel and return its member list."""
        self.open_group(name)
        self.page.click("#groupInfoBtn")
        self.page.wait_for_selector("#groupInfoView:not([hidden])")
        return self.page.inner_text("#groupInfoMembers")

    def add_group_members(self, name: str, usernames: list[str]):
        self.group_member_names(name)
        self.page.fill("#groupAddMemberInput", ", ".join(usernames))
        self.page.click("#groupAddMemberBtn")

    def remove_group_member(self, name: str, username: str):
        self.group_member_names(name)
        self.page.click(f'#groupInfoMembers .member-row:has-text("{username}") .btn-danger')
        wait_until(lambda: username not in self.page.inner_text("#groupInfoMembers"), 20,
                   what=f"{username} to disappear from the member list")

    def leave_group(self, name: str):
        self.group_member_names(name)
        self.page.click("#leaveGroupBtn")
        self.page.wait_for_selector(".confirm-modal")
        self.page.click(".confirm-modal .btn-danger-solid")
        wait_until(lambda: not self.has_group(name), 20, what=f"group {name!r} to disappear after leaving")

    # -- misc -------------------------------------------------------------
    def screenshot(self, path):
        self.page.screenshot(path=str(path))

    def _export_key_material(self) -> list[str]:
        """Base64 of this browser's identity secret keys and conversation keys (for the leak scan only)."""
        try:
            return self.page.evaluate(
                """() => {
                    const s = window.__session;
                    if (!s) return [];
                    const b64 = (u) => btoa(String.fromCharCode(...u));
                    const out = [];
                    if (s.kemKeypair) out.push(b64(s.kemKeypair.secretKey));
                    if (s.signingKeypair) out.push(b64(s.signingKeypair.secretKey));
                    for (const [, info] of s.sessionKeys) out.push(b64(info.key));
                    if (s.keyHistory) for (const [, byEpoch] of s.keyHistory) for (const [, key] of byEpoch) out.push(b64(key));
                    return out;
                }"""
            )
        except Exception:
            return []

    def close(self):
        evidence.record_key_material(self._export_key_material())
        try:
            self.context.close()
        except Exception:
            pass
