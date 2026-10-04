"""
Inbox Dialog

Desktop's Inbox (Phase 19.17C -- Desktop had no Inbox UI at all,
despite the backend and ClientSession's own inbox methods --
request_verification()/load_inbox()/respond_to_inbox() -- already
being fully implemented and tested; this dialog is the presentation
layer only. Mirrors mobile/app.py::show_inbox()'s own split: pending
requests this account can act on ("actionable") shown as cards with
Approve/Deny, versus this account's own earlier requests ("sent")
shown as a plain resolved-status history line -- and reuses the exact
same session methods, never a second inbox implementation.

Approving a verification_request is the ONLY place that can happen
from here: respond_to_inbox() itself is what calls the already-
existing, unweakened confirm_combined_peer_verification() using a
fingerprint THIS client already independently observed -- never
anything carried by the notification. See ClientSession.
respond_to_inbox()'s own docstring.
"""

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from gui.styles import COLOR_ACCENT, COLOR_DANGER, COLOR_ONLINE, COLOR_TEXT_MUTED


class InboxRow(QFrame):
    """
    One notification card: a verification_request ("<User> wants to
    verify their identity") or a group_add_request ("<User> wants to
    add <Member> to <Group>"), each with Approve/Deny -- or, for a
    request this account itself sent, a plain resolved-status line.
    No packet names or database ids are ever shown.
    """

    def __init__(self, session, notification, on_responded, parent=None):
        super().__init__(parent)

        self.session = session
        self.notification = notification
        self.on_responded = on_responded

        self.setObjectName("Card")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        requester = notification.get("requester_username", "Someone")
        is_group_request = notification.get("type") == "group_add_request"

        kind_label = QLabel(
            "GROUP MEMBER REQUEST" if is_group_request else "VERIFICATION REQUEST"
        )
        kind_label.setTextFormat(Qt.PlainText)
        kind_label.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-size: 9pt; font-weight: 700; "
            "letter-spacing: 0.5px;"
        )
        layout.addWidget(kind_label)

        if is_group_request:
            text = (
                f"{requester} wants to add "
                f"{notification.get('candidate_username', 'a member')} "
                f"to {notification.get('group_name', 'the group')}"
            )
        else:
            text = f"{requester} wants to verify their identity"

        body_label = QLabel(text)
        body_label.setTextFormat(Qt.PlainText)
        body_label.setWordWrap(True)
        body_label.setStyleSheet("font-size: 10.5pt; font-weight: 500;")
        layout.addWidget(body_label)

        self.status_label = QLabel("")
        self.status_label.setTextFormat(Qt.PlainText)
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet(f"color: {COLOR_DANGER}; font-size: 9pt;")
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        status = notification.get("status")

        if status == "pending" and requester != session.username:

            button_row = QHBoxLayout()
            button_row.setSpacing(8)

            approve_button = QPushButton("Approve")
            approve_button.setCursor(Qt.PointingHandCursor)
            approve_button.clicked.connect(lambda: self._respond(True))
            button_row.addWidget(approve_button)

            deny_button = QPushButton("Deny")
            deny_button.setObjectName("SecondaryButton")
            deny_button.setCursor(Qt.PointingHandCursor)
            deny_button.clicked.connect(lambda: self._respond(False))
            button_row.addWidget(deny_button)

            layout.addLayout(button_row)

        else:

            resolved_color = COLOR_ONLINE if status == "approved" else COLOR_TEXT_MUTED
            resolved_text = {
                "approved": "Approved",
                "denied": "Denied",
                "pending": "Waiting for a response...",
            }.get(status, status or "")
            resolved_label = QLabel(resolved_text)
            resolved_label.setTextFormat(Qt.PlainText)
            resolved_label.setStyleSheet(
                f"color: {resolved_color}; font-size: 9pt; font-weight: 700;"
            )
            layout.addWidget(resolved_label)

    def _respond(self, approve):

        # PHASE 19.22 -- verification-flow race: the requester's
        # identity packet and this notification's own arrival are two
        # independent, asynchronously-relayed things (see
        # ClientSession.respond_to_inbox()'s own docstring for why the
        # actual gate below never trusts anything but a freshly
        # observed identity -- that check is NOT weakened by this).
        # With both users genuinely online, the identity is virtually
        # always seconds -- not missing -- so give it a short, bounded
        # chance to land instead of surfacing a fail-closed error for
        # what is really just an ordinary timing race. If the
        # requester truly isn't observed once this window elapses
        # (actually stale/offline), respond_to_inbox() below still
        # raises the exact same, unchanged error.
        if approve and self.notification.get("type") == "verification_request":
            requester = self.notification.get("requester_username")
            if requester and not self.session.has_observed_combined_identity(requester):
                self.status_label.setStyleSheet(
                    f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;"
                )
                self.status_label.setText("Confirming identity...")
                self.status_label.setVisible(True)
                deadline = time.monotonic() + 2.0
                while (
                    not self.session.has_observed_combined_identity(requester)
                    and time.monotonic() < deadline
                ):
                    QApplication.processEvents()
                    time.sleep(0.05)
                self.status_label.setVisible(False)
                self.status_label.setStyleSheet(
                    f"color: {COLOR_DANGER}; font-size: 9pt;"
                )

        try:
            self.session.respond_to_inbox(self.notification, approve)
        except Exception as error:  # noqa: BLE001
            self.status_label.setText(str(error))
            self.status_label.setVisible(True)
            return

        self.on_responded()


class InboxDialog(QDialog):
    """
    Lists every inbox notification where this account is either the
    recipient or the original requester (session.load_inbox()) --
    pending, actionable ones first, then a resolved-history section
    for requests this account itself sent. Refreshes automatically
    while open if session.inbox_updated fires (a live push, or the
    resolution of one of this account's own earlier requests) -- not
    only on manual reopen, since that gap (never connecting this
    signal to anything) is exactly what left Android's own Inbox only
    ever refreshing on a manual pull.
    """

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Inbox")
        self.resize(420, 480)

        self.build_ui()
        self.refresh()

        self.session.inbox_updated.connect(self._on_inbox_updated)

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QVBoxLayout(self)

        self.list_widget = QListWidget()
        self.list_widget.setSpacing(6)
        layout.addWidget(self.list_widget)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color: {COLOR_DANGER};")
        self.error_label.setVisible(False)
        layout.addWidget(self.error_label)

        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def refresh(self):

        self.list_widget.clear()

        try:
            notifications = self.session.load_inbox()
        except Exception as error:  # noqa: BLE001
            self.error_label.setText(str(error))
            self.error_label.setVisible(True)
            return

        self.error_label.setVisible(False)

        my_username = self.session.username

        # A notification never names its own recipient explicitly
        # (server/client_handler.py's own _serialize_*_notification()
        # docstrings) -- if this account is not the requester, it can
        # only be the recipient, since load_inbox() is already scoped
        # to "one of the two parties".
        actionable = [
            n for n in notifications
            if n.get("status") == "pending" and n.get("requester_username") != my_username
        ]
        sent = [n for n in notifications if n.get("requester_username") == my_username]

        if not actionable and not sent:
            placeholder = QListWidgetItem("Nothing here yet.")
            placeholder.setFlags(Qt.NoItemFlags)
            self.list_widget.addItem(placeholder)
            return

        for notification in actionable + sent:
            self._add_row(notification)

    # ==========================================================
    # Helpers
    # ==========================================================

    def _add_row(self, notification):

        item = QListWidgetItem()
        self.list_widget.addItem(item)

        row = InboxRow(self.session, notification, self.refresh, self)

        item.setSizeHint(row.sizeHint())

        self.list_widget.setItemWidget(item, row)

    # ==========================================================
    # Events
    # ==========================================================

    def _on_inbox_updated(self, notification):
        self.refresh()

    def closeEvent(self, event):

        try:
            self.session.inbox_updated.disconnect(self._on_inbox_updated)
        except (RuntimeError, TypeError):
            pass

        super().closeEvent(event)
