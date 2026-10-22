"""
Group Info Dialog (Phase 19.18 -- Desktop Group Admin parity).

Desktop's client/session.py already has remove_group_member() (Phase
19.13, shared server-side enforcement with Android/Web -- see
server/client_handler.py::handle_group_remove_member()'s own
docstring: caller's admin role is always re-derived server-side,
never trusted from whether this dialog happens to show a Remove
button), and the conversation-list/group-create wire packets already
carry admin_username/creator. Only the Desktop GUI itself had no view
of a group's membership at all, and no way to call the existing
method -- this dialog is that missing piece, mirroring web/client/
main.js::renderGroupInfo()'s member-row-plus-admin-only-Remove-button
shape.

No optimistic local mutation: server/client_handler.py::handle_group_
remove_member() broadcasts group_member_left to every remaining
member's socket, INCLUDING the admin's own, before it replies to the
admin's own remove_group_member() request -- so by the time that
blocking send_request() call returns, ClientSession.handle_group_
member_left() has already refreshed conversation_store for us. This
dialog only ever re-reads conversation_store after a successful
result; it never mutates the member list itself.
"""

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from client.session import PEER_KEY_STATE_CHANGED
from gui.styles import COLOR_ACCENT, COLOR_BORDER, COLOR_DANGER, COLOR_PANEL_ALT, COLOR_TEXT_MUTED
from gui.verify_identity_dialog import VerifyIdentityDialog
from storage.secure_key_store import PEER_STATE_VERIFIED

# How each member stands with THIS account. A group key is only ever wrapped for, and accepted from,
# a verified identity, so this is what decides whether the key can reach them.
_TRUST_LABELS = {
    PEER_STATE_VERIFIED: "✓ Verified",
    PEER_KEY_STATE_CHANGED: "Key changed",
    None: "Not seen yet",
}


class GroupInfoDialog(QDialog):
    """
    Read-only member list for ``conversation_id``, with an admin-only
    "Remove" button per non-self, non-admin member. Not live-updating
    while open beyond what conversation_store's own conversations_
    changed signal already drives (_refresh()) -- there is no separate
    polling or push channel this dialog needs of its own.
    """

    def __init__(self, session, conversation_id, parent=None):
        super().__init__(parent)

        self.session = session
        self.conversation_id = conversation_id

        self.setWindowTitle("Group Info")

        self._status_label = QLabel("")
        self._status_label.setTextFormat(Qt.PlainText)
        self._status_label.setWordWrap(True)

        self._member_list = QListWidget()

        layout = QVBoxLayout(self)
        self._name_label = QLabel("")
        layout.addWidget(self._name_label)

        # Shown only while this account cannot read the group yet: says why, and what finishes it.
        self._key_notice = QLabel(
            "You do not have this group's key yet, so you cannot read or send messages in it. It arrives "
            "once you and the member who holds it (usually the admin) have verified each other — use "
            "Verify next to their name."
        )
        self._key_notice.setObjectName("GroupKeyNotice")
        self._key_notice.setTextFormat(Qt.PlainText)
        self._key_notice.setWordWrap(True)
        self._key_notice.setStyleSheet(
            f"background: {COLOR_PANEL_ALT}; border: 1px solid {COLOR_BORDER}; border-radius: 8px; "
            f"color: {COLOR_TEXT_MUTED}; padding: 8px 10px;"
        )
        self._key_notice.setVisible(False)
        layout.addWidget(self._key_notice)

        # Invitations this account sent for this group that are still waiting for the person's decision.
        self._pending_label = QLabel("")
        self._pending_label.setObjectName("GroupPendingInvitations")
        self._pending_label.setTextFormat(Qt.PlainText)
        self._pending_label.setWordWrap(True)
        self._pending_label.setStyleSheet(self._key_notice.styleSheet())
        self._pending_label.setVisible(False)
        layout.addWidget(self._pending_label)

        layout.addWidget(QLabel("Members"))
        layout.addWidget(self._member_list)
        layout.addWidget(self._status_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

        self.session.conversation_store.conversations_changed.connect(self._refresh)

        # A key can arrive (or a verification complete) without the member list changing.
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(2000)
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh_timer.start()

        self._refresh()

    def _refresh(self):
        summary = self.session.conversation_store.get(self.conversation_id)

        if summary is None or not summary.is_group:
            # The group this dialog was opened for no longer exists for
            # this client (e.g. this client itself was removed while the
            # dialog was open) -- reflect that rather than show stale rows.
            self._name_label.setText("")
            self._member_list.clear()
            self._status_label.setText("This group is no longer available.")
            return

        self._name_label.setText(f"Group: {summary.group_name}")

        self._key_notice.setVisible(not self.session.key_manager.has_key(self.conversation_id))

        waiting = self._waiting_invitees()
        self._pending_label.setVisible(bool(waiting))
        self._pending_label.setText(
            f"Waiting for approval: {', '.join(waiting)}. They join the group only if they approve "
            "the invitation in their Inbox." if waiting else ""
        )

        self._member_list.clear()

        own_username = self.session.get_username()
        is_self_admin = summary.admin is not None and summary.admin == own_username

        members = list(summary.participants or [])
        if own_username not in members:
            members = members + [own_username]

        for username in sorted(members):
            self._add_member_row(username, summary.admin, is_self_admin, own_username)

    def _add_member_row(self, username, admin, is_self_admin, own_username):
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(4, 2, 4, 2)

        label_text = username
        if username == admin:
            label_text += "  (admin)"
        if username == own_username:
            label_text += "  (you)"

        row_layout.addWidget(QLabel(label_text))
        row_layout.addStretch()

        if username != own_username:
            state = self.session.get_peer_verification_state(username)
            if state is not None and state != PEER_STATE_VERIFIED and state != PEER_KEY_STATE_CHANGED:
                text = "Not verified"
            else:
                text = _TRUST_LABELS.get(state, "Not seen yet")
            trust = QLabel(text)
            trust.setObjectName("MemberTrust")
            trust.setTextFormat(Qt.PlainText)
            trust.setStyleSheet(
                f"color: {COLOR_ACCENT if state == PEER_STATE_VERIFIED else (COLOR_DANGER if state == PEER_KEY_STATE_CHANGED else COLOR_TEXT_MUTED)};"
                " font-size: 9pt;"
            )
            row_layout.addWidget(trust)

            if state != PEER_STATE_VERIFIED:
                verify_button = QPushButton("Verify")
                verify_button.setObjectName("MemberVerifyButton")
                verify_button.setCursor(Qt.PointingHandCursor)
                verify_button.setAccessibleName(f"Verify {username} to share group keys")
                verify_button.clicked.connect(
                    lambda checked=False, target=username: self._handle_verify(target)
                )
                row_layout.addWidget(verify_button)

        # Admin-only, and never a self-removal button -- the server
        # rejects both a non-admin caller and an admin trying to
        # remove themselves through this path anyway (handle_group_
        # remove_member()'s own docstring), so hiding both here is a
        # convenience for the common case, never the enforcement.
        if is_self_admin and username != admin and username != own_username:
            remove_button = QPushButton("Remove")
            remove_button.setCursor(Qt.PointingHandCursor)
            remove_button.clicked.connect(
                lambda checked=False, target=username: self._handle_remove(target)
            )
            row_layout.addWidget(remove_button)

        item = QListWidgetItem()
        item.setSizeHint(row.sizeHint())
        self._member_list.addItem(item)
        self._member_list.setItemWidget(item, row)

    def _waiting_invitees(self):
        """Names of the people this account invited to this group who have not answered yet."""

        try:
            notifications = self.session.load_inbox()
        except Exception:  # noqa: BLE001
            return []

        me = self.session.get_username()
        names = []
        for n in notifications:
            if (
                n.get("type") == "group_invitation" and n.get("status") == "pending"
                and n.get("conversation_id") == self.conversation_id and n.get("requester_username") == me
            ):
                handle = n.get("recipient_username") or n.get("candidate_username")
                lookup = getattr(self.session, "display_name_for", None)
                try:
                    shown = lookup(handle) if lookup else None
                except Exception:  # noqa: BLE001
                    shown = None
                names.append(shown if isinstance(shown, str) and shown else handle)
        return names

    def _handle_verify(self, target_username):
        """The same Verify Identity window a direct chat uses; it alone confirms a verification."""

        state = self.session.get_peer_verification_state(target_username)
        VerifyIdentityDialog(self.session, target_username, state, self).exec()
        self._refresh()

    def _handle_remove(self, target_username):
        self._status_label.setText(f"Removing {target_username}...")

        response = self.session.remove_group_member(self.conversation_id, target_username)

        if not response.get("success"):
            self._status_label.setText(response.get("error") or "Could not remove member.")
            return

        self._status_label.setText(f"Removed {target_username}.")
        # ClientSession.handle_group_member_left() has already updated
        # conversation_store by the time the blocking call above
        # returns (see module docstring) -- conversations_changed has
        # therefore already fired _refresh() for us; nothing further
        # to do here.
