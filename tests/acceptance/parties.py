"""One interface over a Website user and a Desktop-EXE user.

Every method performs real UI actions (Playwright for the Website, Windows UI
Automation for the packaged executable), so a scenario can mix any combination
of clients without caring which is which.
"""

from __future__ import annotations

import re

from tests.acceptance import desktop_driver as dd
from tests.acceptance import web_driver as wd
from tests.acceptance.web_driver import wait_until


def normalise(number: str) -> str:
    return re.sub(r"[^0-9A-F]", "", number.upper())


class WebParty:
    kind = "web"

    def __init__(self, user: wd.WebUser):
        self.user = user
        self.username, self.phone, self.password = user.username, user.phone, user.password

    # lifecycle
    def register(self):
        self.user.register()

    def login(self):
        self.user.login()

    def logout(self):
        self.user.logout()
        wait_until(lambda: self.user.page.is_visible("#connectBtn"), 20, what="the login form after logout")

    def close(self):
        self.user.close()

    # conversation
    def open_chat_with(self, other: "Party"):
        self.user.open_chat(other.username)

    def peer_fingerprint(self) -> str:
        return normalise(wd.safety_digits(self.user.safety_number()))

    def own_fingerprint(self) -> str:
        return normalise(self.user.own_fingerprint())

    def confirm_peer(self):
        self.user.confirm_match()

    def start_secure_session(self):
        self.user.establish_key()

    def send(self, text: str):
        self.user.send(text)

    def wait_for_text(self, text: str, timeout: float = 30.0):
        self.user.wait_for_message(text, timeout)

    def visible_text(self) -> str:
        return self.user.messages()

    def errors(self) -> list[str]:
        return self.user.page_errors + self.user.console_errors


class DesktopParty:
    kind = "desktop"

    def __init__(self, app: dd.DesktopApp):
        self.app = app
        self.username, self.phone, self.password = app.username, app.phone, app.password

    def register(self):
        dd.register(self.app, self.username, self.phone, self.password)

    def login(self):
        dd.login(self.app, self.phone, self.password)

    def logout(self):
        dd.logout(self.app)

    def restart(self):
        """Quit and relaunch the application (same key store), leaving it at the login form."""
        self.app.restart()

    def close(self):
        self.app.stop()

    def open_chat_with(self, other: "Party"):
        dd.open_chat_by_phone(self.app, other.phone)

    def peer_fingerprint(self) -> str:
        number = normalise(dd.read_fingerprint_in_verify_dialog(self.app))
        # The dialog stays open so that confirm_peer() acts on exactly the number that was read.
        return number

    def own_fingerprint(self) -> str:
        return normalise(dd.read_own_fingerprint(self.app))

    def confirm_peer(self):
        dd.confirm_fingerprint_match(self.app)

    def start_secure_session(self):
        # The Desktop client establishes the session key itself once both sides are verified.
        pass

    def send(self, text: str):
        dd.send_message(self.app, text)

    def wait_for_text(self, text: str, timeout: float = 30.0):
        self.app.wait_for(lambda: text in dd.conversation_text(self.app), timeout=timeout,
                          what=f"message {text!r} on the Desktop")

    def visible_text(self) -> str:
        return dd.conversation_text(self.app)

    def errors(self) -> list[str]:
        return [] if self.app.alive() else [f"Desktop process exited with code {self.app.proc.returncode}"]


Party = WebParty | DesktopParty


def verify_pair(a: Party, b: Party):
    """Mutual out-of-band verification, as two people would do it.

    Each side opens the chat, reads the number its own app shows for the other person, and that
    must equal the number the other person's app reports as their own. Only then does each confirm.
    """
    a.open_chat_with(b)
    b.open_chat_with(a)
    shown_to_a = a.peer_fingerprint()
    assert shown_to_a == b.own_fingerprint(), f"{a.username} was shown a different identity for {b.username}"
    a.confirm_peer()
    shown_to_b = b.peer_fingerprint()
    assert shown_to_b == a.own_fingerprint(), f"{b.username} was shown a different identity for {a.username}"
    b.confirm_peer()


def converse(a: Party, b: Party, tag: str):
    """One message each way; each must appear on the receiving client."""
    a.start_secure_session()
    b.start_secure_session()
    first, second = f"{tag}: {a.username} to {b.username}", f"{tag}: {b.username} to {a.username}"
    a.send(first)
    b.wait_for_text(first)
    b.send(second)
    a.wait_for_text(second)
