"""
Terminal UI Test

Manual smoke-test script for the live-updating terminal UI, without
starting the full chat application. This is not an automated pytest
suite (it defines no test_* functions) -- it launches a blocking,
full-screen prompt_toolkit Application, so none of that must ever run
merely from pytest importing/collecting this file:

  - pytest.importorskip() below skips this module cleanly during
    collection if prompt_toolkit isn't installed, instead of crashing.
  - The demo itself only runs under `if __name__ == "__main__"`, so
    even in an environment where prompt_toolkit IS installed, pytest
    collection still won't block forever inside ui.run().

Run manually with:
    python tests/terminal_ui_test.py
"""

import threading
import time

import pytest

# Must happen before importing utils.terminal_ui, which imports
# prompt_toolkit at module level -- that's the actual crash site
# during pytest collection when the dependency isn't installed.
pytest.importorskip(
    "prompt_toolkit",
    reason="prompt_toolkit is only required for this manual terminal UI demo.",
)

from utils.terminal_ui import TerminalUI


class FakeSession:

    def __init__(self):

        self.online_users = []


def simulate_users(session, ui):

    time.sleep(2)

    session.online_users = [
        "Vignesh T"
    ]

    ui.invalidate()

    time.sleep(2)

    session.online_users = [
        "Vignesh T",
        "Ramya"
    ]

    ui.invalidate()

    time.sleep(2)

    session.online_users = [
        "Vignesh T",
        "Ramya",
        "Thiyagarajan"
    ]

    ui.invalidate()

    time.sleep(2)

    session.online_users = [
        "Ramya",
        "Thiyagarajan"
    ]

    ui.invalidate()

    time.sleep(2)

    session.online_users = [
        "Thiyagarajan"
    ]

    ui.invalidate()

    time.sleep(2)

    session.online_users = []

    ui.invalidate()


if __name__ == "__main__":

    session = FakeSession()

    ui = TerminalUI(session)

    threading.Thread(
        target=simulate_users,
        args=(session, ui),
        daemon=True
    ).start()

    ui.run()
