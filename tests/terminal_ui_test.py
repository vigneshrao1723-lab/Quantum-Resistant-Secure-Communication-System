"""
Terminal UI Test

Tests the live updating terminal UI
without starting the chat application.
"""

import threading
import time

from utils.terminal_ui import TerminalUI


class FakeSession:

    def __init__(self):

        self.online_users = []


session = FakeSession()

ui = TerminalUI(session)


def simulate_users():

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


threading.Thread(
    target=simulate_users,
    daemon=True
).start()

ui.run()