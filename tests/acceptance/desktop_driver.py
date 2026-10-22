"""Drive the real Desktop GUI (source run or packaged EXE) through Windows UI Automation.

``DesktopApp`` launches the application as a separate process, so what is
exercised is the shipped binary and its real widgets, not an in-process test
double. A single long-lived PowerShell process (``uia_agent.ps1``) performs the
automation; commands and replies are JSON lines.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from tests.acceptance import evidence

_AGENT = Path(__file__).with_name("uia_agent.ps1")


class UiaError(RuntimeError):
    pass


class UiaAgent:
    def __init__(self):
        self._proc = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(_AGENT)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", bufsize=1,
        )

    def call(self, **command) -> dict:
        self._proc.stdin.write(json.dumps(command) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            raise UiaError("automation agent exited")
        reply = json.loads(line)
        if not reply.get("ok"):
            raise UiaError(reply.get("error", "unknown automation error"))
        return reply

    def close(self):
        try:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()


class DesktopApp:
    """One running Desktop client with its own key store."""

    def __init__(self, command: list[str], env: dict[str, str], agent: UiaAgent, cwd: str | None = None):
        self.agent = agent
        self._command, self._env, self._cwd = command, env, cwd
        self.proc = subprocess.Popen(command, env=self._launch_env(), cwd=cwd)
        self.pid = self.proc.pid
        self._wait_window()

    def _launch_env(self) -> dict:
        """The environment for the application: inherited, plus ours, but never a Qt platform override.

        A test process may have forced Qt's headless "offscreen" platform for its own widgets; an
        application started from it would then render to nowhere and have no window to automate.
        """
        env = {**os.environ, **self._env}
        env.pop("QT_QPA_PLATFORM", None)
        return env

    def restart(self):
        """Close the application and start it again with the same settings and key store."""
        self.stop()
        self.proc = subprocess.Popen(self._command, env=self._launch_env(), cwd=self._cwd)
        self.pid = self.proc.pid
        self._wait_window()

    def _wait_window(self, timeout: float = 90.0):
        # Generous: the first launch of a freshly built executable can be held up for tens of seconds
        # while the operating system's real-time scanner inspects it.
        started = time.monotonic()
        deadline = started + timeout
        last_error = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise UiaError(f"application exited early with code {self.proc.returncode}")
            try:
                if self.agent.call(cmd="windows", pid=self.pid)["windows"]:
                    return
            except UiaError as error:
                last_error = error
            time.sleep(0.3)
        raise UiaError(
            f"application window did not appear within {time.monotonic() - started:.0f}s "
            f"(process alive: {self.proc.poll() is None}; last automation error: {last_error})"
        )

    # -- primitives -------------------------------------------------------
    def windows(self) -> list[str]:
        return [w["title"] for w in self.agent.call(cmd="windows", pid=self.pid)["windows"]]

    def tree(self, window: str | None = None) -> list[dict]:
        return self.agent.call(cmd="tree", pid=self.pid, window=window)["elements"]

    def click(self, window: str | None = None, mouse: bool = False, **by):
        self.agent.call(cmd="click", pid=self.pid, window=window, by=by, mouse=mouse)

    def set_text(self, text: str, window: str | None = None, **by):
        self.agent.call(cmd="set_text", pid=self.pid, window=window, by=by, text=text)

    def get(self, window: str | None = None, **by) -> dict:
        return self.agent.call(cmd="get_text", pid=self.pid, window=window, by=by)["element"]

    def keys(self, keys: str, window: str | None = None, **by):
        self.agent.call(cmd="key", pid=self.pid, window=window, by=by or None, keys=keys)

    def wait_for(self, predicate, timeout: float = 20.0, interval: float = 0.4, what: str = "condition"):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                result = predicate()
                if result:
                    return result
            except UiaError as error:
                last = error
            time.sleep(interval)
        raise UiaError(f"timed out waiting for {what}" + (f" ({last})" if last else ""))

    def screenshot(self, path, window: str | None = None) -> tuple[int, int]:
        """Save a PNG of the application window as it is on screen; returns (width, height)."""
        reply = self.agent.call(cmd="screenshot", pid=self.pid, window=window, path=str(path))
        return reply["width"], reply["height"]

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self):
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---------------------------------------------------------------------------
# User-level workflows on the Desktop client (each step is a real UI action)
# ---------------------------------------------------------------------------

def register(app: DesktopApp, username: str, phone: str, password: str):
    app.wait_for(lambda: app.get(id="AuthModeToggle"), what="login form")
    app.click(id="AuthModeToggle")
    app.wait_for(lambda: app.get(id="UsernameInput"), what="registration form")
    app.set_text(username, id="UsernameInput")
    app.set_text(phone, id="PhoneInput")
    app.set_text(password, id="PasswordInput")
    app.set_text(password, id="ConfirmPasswordInput")
    app.click(id="AuthPrimaryAction")
    # After a successful registration the form returns to Login with the phone pre-filled.
    app.wait_for(lambda: app.get(id="AuthPrimaryAction")["name"] == "Login", timeout=30, what="return to login form")


def login(app: DesktopApp, phone: str, password: str):
    app.set_text(phone, id="PhoneInput")
    app.set_text(password, id="PasswordInput")
    app.click(id="AuthPrimaryAction")
    app.wait_for(lambda: app.get(id="StatusBarWidget.ConnectionStatus"), timeout=40, what="main window after login")


def open_chat_by_phone(app: DesktopApp, phone: str):
    app.click(name="New chat")
    app.wait_for(lambda: app.get(id="FindUserDialog.QLineEdit"), what="Find User dialog")
    app.set_text(phone, id="FindUserDialog.QLineEdit")
    app.click(id="FindUserDialog", name="Search")
    app.wait_for(lambda: app.get(id="FindUserDialog", name="Open Chat")["enabled"], what="search result")
    app.click(id="FindUserDialog", name="Open Chat")
    # A verified contact has no "Verify Identity" button, so the composer is the reliable sign.
    app.wait_for(lambda: _exists(app, id="ComposerInput"), what="chat view")


def read_fingerprint_in_verify_dialog(app: DesktopApp) -> str:
    app.click(name="Verify Identity")
    app.wait_for(lambda: app.get(id="VerifyIdentityDialog.Fingerprint"), what="Verify Identity dialog")
    return app.get(id="VerifyIdentityDialog.Fingerprint")["name"]


def confirm_fingerprint_match(app: DesktopApp):
    app.click(id="VerifyIdentityDialog", name="Yes, This Matches -- Verify")


def send_message(app: DesktopApp, text: str):
    evidence.record_plaintext(text)
    app.set_text(text, id="ComposerInput")
    app.wait_for(lambda: app.get(id="SendButton")["enabled"], what="send button enabled")
    app.click(id="SendButton")


def conversation_text(app: DesktopApp) -> str:
    """All text currently rendered in the message list."""
    parts = []
    for e in app.tree():
        if "MessagesPane" in (e["id"] or "") and e["name"]:
            parts.append(e["name"])
    return "\n".join(parts)


def open_settings(app: DesktopApp):
    app.click(id="NavRail.RailButton", name="Settings")
    app.wait_for(lambda: app.get(id="AccountSettingsDialog", name="Logout"), what="Settings dialog")


def close_settings(app: DesktopApp):
    app.click(id="AccountSettingsDialog", name="Close")
    app.wait_for(lambda: not _exists(app, id="AccountSettingsDialog", name="Logout"), what="Settings dialog to close")


def read_own_fingerprint(app: DesktopApp) -> str:
    """The user's own safety number, read where a person reads it: in the verification window of
    the contact it is for, behind "Show my safety number" (a conversation must be open). It is not
    in Settings."""
    app.click(name="Re-verify" if _exists(app, name="Re-verify") else "Verify Identity")
    app.wait_for(lambda: app.get(id="VerifyIdentityDialog", name="Show my safety number"), what="Verify Identity dialog")
    assert not _exists(app, id="OwnSafetyNumber"), "the own safety number was on screen before it was asked for"
    app.click(id="VerifyIdentityDialog", name="Show my safety number")
    app.wait_for(lambda: app.get(id="OwnSafetyNumber"), what="the own safety number")
    try:
        return app.get(id="OwnSafetyNumber")["name"]
    finally:
        app.click(id="VerifyIdentityDialog", name="Cancel")
        app.wait_for(lambda: not _exists(app, id="VerifyIdentityDialog.Fingerprint"), what="Verify Identity dialog to close")


def logout(app: DesktopApp):
    open_settings(app)
    app.click(id="AccountSettingsDialog", name="Logout")
    app.wait_for(lambda: app.get(id="AuthPrimaryAction"), timeout=20, what="return to the login form")


def _exists(app: DesktopApp, **by) -> bool:
    try:
        app.get(**by)
        return True
    except UiaError:
        return False


def open_conversation(app: DesktopApp, name: str):
    """Open a conversation from the sidebar by clicking its row (found by its accessible text)."""
    app.wait_for(lambda: app.get(id="ConversationList", type="ListItem", name_contains=name),
                 timeout=40, what=f"a sidebar row for {name!r}")
    app.click(id="ConversationList", type="ListItem", name_contains=name, mouse=True)
    app.wait_for(lambda: any(name in (e["name"] or "") for e in app.tree() if "ChatHeader" in (e["id"] or "")),
                 what=f"the {name!r} conversation to open")


def approve_first_invitation(app: DesktopApp):
    """Answer the first pending Inbox item with Approve, as a person does: open the Inbox, press
    Approve on the card, close the Inbox. (Joining a group needs the person's own approval.)"""
    app.click(id="NavRail.RailButton", name="Inbox")
    app.wait_for(lambda: app.get(name_contains="Approve: "), timeout=40, what="an invitation in the Desktop's Inbox")
    app.click(name_contains="Approve: ")
    app.wait_for(lambda: not _exists(app, name_contains="Approve: "), timeout=40, what="the invitation to be answered")
    app.keys("{ESC}")


def sidebar_rows(app: DesktopApp) -> list[str]:
    return [e["name"] for e in app.tree() if "ConversationList" in (e["id"] or "") and e["type"] == "ListItem"]
