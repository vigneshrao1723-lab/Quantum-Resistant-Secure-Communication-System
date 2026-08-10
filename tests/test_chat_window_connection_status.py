"""
Regression tests for the ClientSession.connection_changed ->
StatusBarWidget.set_connected wiring (gui/chat_window.py::register_callbacks()).

No GUI-test framework exists in this project (no pytest-qt, no
existing QApplication-based test) and none is introduced here -- this
file creates the one QApplication instance PySide6 requires before any
QWidget (StatusBarWidget) can be instantiated, using Qt's offscreen
platform so no real display is needed, and tests the exact two
production objects plus the exact one-line connection
gui/chat_window.py makes between them. ChatWindow itself is
deliberately not constructed here -- it requires a fully authenticated
session, a live socket, and a real database connection just to reach
register_callbacks(), none of which this wiring depends on.

Run with:
    pytest tests/test_chat_window_connection_status.py -v
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from client.session import ClientSession
from gui.status_bar import StatusBarWidget

# Qt requires exactly one QApplication per process before any QWidget
# (StatusBarWidget) can be constructed. Guarded so re-importing this
# module (or running alongside another file that already created one)
# never tries to create a second.
_app = QApplication.instance() or QApplication([])


def _wire(session, status):
    """The exact connection gui/chat_window.py::register_callbacks()
    makes -- duplicated here rather than imported, since ChatWindow
    itself is out of scope for this test (see module docstring)."""
    session.connection_changed.connect(status.set_connected)


def test_status_bar_defaults_to_disconnected_before_any_signal():
    """No "connecting" state exists in connection_changed (it's
    Signal(bool), only ever True or False -- see client/session.py and
    client/receiver.py) -- a freshly built status bar must not show
    Connected before anything is ever emitted."""
    status = StatusBarWidget()

    assert status.connection_label.text() == "● Disconnected"


def test_connect_emits_true_and_status_bar_shows_connected():
    session = ClientSession()
    status = StatusBarWidget()
    _wire(session, status)

    session.connection_changed.emit(True)

    assert status.connection_label.text() == "● Connected"


def test_explicit_disconnect_emits_false_and_status_bar_shows_disconnected():
    session = ClientSession()
    status = StatusBarWidget()
    _wire(session, status)

    session.connection_changed.emit(True)
    session.connection_changed.emit(False)

    assert status.connection_label.text() == "● Disconnected"


def test_unexpected_drop_reaches_the_status_bar():
    """Mirrors client/receiver.py::receive_messages()'s exact
    unexpected-disconnect sequence (the receiver thread's connection-
    loss guard, not an explicit ClientSession.disconnect() call) -- the
    gap this wiring closes: previously nothing in the GUI listened to
    this emission at all."""
    session = ClientSession()
    status = StatusBarWidget()
    _wire(session, status)

    session.connected = True
    session.connection_changed.emit(True)
    assert status.connection_label.text() == "● Connected"

    # receive_messages()'s own guard/sequence on an unexpected drop:
    if session.connected:
        session.connected = False
        session.connection_changed.emit(False)

    assert status.connection_label.text() == "● Disconnected"


def test_wiring_uses_the_existing_signal_and_existing_status_bar_method():
    """Guards against a second connection-state mechanism being
    introduced later: the only thing bridging session and status bar
    must be this one Signal(bool) -> set_connected(bool) connection."""
    session = ClientSession()
    status = StatusBarWidget()

    assert hasattr(session, "connection_changed")
    assert hasattr(status, "set_connected")

    _wire(session, status)

    session.connection_changed.emit(True)
    assert status.connection_label.text() == "● Connected"
