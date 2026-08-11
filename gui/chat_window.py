"""
Chat Window

Main chat interface for the Quantum-Resistant
Secure Communication System.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QFrame,
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QMessageBox,
    QPushButton,
)

from domain.conversation_summary import ConversationSummary
from domain.payload_type import PayloadType
from gui.add_members_dialog import AddMembersDialog
from gui.conversation_list_widget import ConversationListWidget
from gui.create_group_dialog import CreateGroupDialog
from gui.find_user_dialog import FindUserDialog
from gui.message_widget import MessageWidget
from gui.input_bar import InputBar
from gui.status_bar import StatusBarWidget
from gui.styles import COLOR_TEXT_MUTED


class ChatWindow(QWidget):
    """
    Main chat interface.
    """

    logout_requested = Signal()

    def __init__(self, session):
        super().__init__()

        self.session = session

        # C2 -- Read Receipts: usernames who have confirmed reading
        # the currently-open conversation "up to now" since it was
        # opened -- see handle_read_receipt_updated(). Reset every
        # time open_conversation() runs, since bubbles are always
        # re-rendered fresh from history at that point (already
        # reflecting current status), making any prior accumulation
        # stale.
        self._read_receipt_readers = set()

        self.build_ui()

        self.connect_signals()

        self.register_callbacks()

        self.initialize_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        root_layout = QHBoxLayout(self)

        root_layout.setContentsMargins(16, 16, 16, 16)

        root_layout.setSpacing(16)

        # -----------------------------
        # Left Panel
        # -----------------------------

        left_panel = QFrame()

        left_panel.setObjectName("Panel")

        left_layout = QVBoxLayout(left_panel)

        left_layout.setContentsMargins(14, 14, 14, 14)

        users_title = QLabel("CONVERSATIONS")

        users_title.setObjectName("SectionTitle")

        self.find_user_button = QPushButton("Find User")

        self.find_user_button.setCursor(Qt.PointingHandCursor)

        self.find_user_button.clicked.connect(
            self.handle_find_user
        )

        self.new_group_button = QPushButton("+ Group")

        self.new_group_button.setCursor(Qt.PointingHandCursor)

        self.new_group_button.clicked.connect(
            self.handle_create_group
        )

        conversations_header = QHBoxLayout()

        conversations_header.addWidget(users_title)

        conversations_header.addStretch()

        conversations_header.addWidget(self.find_user_button)

        conversations_header.addWidget(self.new_group_button)

        self.conversation_list = ConversationListWidget()

        left_layout.addLayout(conversations_header)

        left_layout.addWidget(self.conversation_list)

        # -----------------------------
        # Right Panel
        # -----------------------------

        right_layout = QVBoxLayout()

        right_layout.setSpacing(12)

        # Header: app title + current chat partner

        header = QFrame()

        header.setObjectName("Panel")

        header_layout = QVBoxLayout(header)

        header_layout.setContentsMargins(18, 12, 18, 12)

        header_layout.setSpacing(2)

        app_title = QLabel("Quantum-Resistant Secure Chat")

        app_title.setStyleSheet(
            "font-size: 15px; font-weight: 700;"
        )

        self.add_members_button = QPushButton("Add Members")

        self.add_members_button.setCursor(Qt.PointingHandCursor)

        self.add_members_button.clicked.connect(
            self.handle_add_members
        )

        self.add_members_button.setVisible(False)

        self.leave_group_button = QPushButton("Leave Group")

        self.leave_group_button.setCursor(Qt.PointingHandCursor)

        self.leave_group_button.clicked.connect(
            self.handle_leave_group
        )

        self.leave_group_button.setVisible(False)

        self.logout_button = QPushButton("Logout")

        self.logout_button.setCursor(Qt.PointingHandCursor)

        self.logout_button.clicked.connect(
            self.logout_requested.emit
        )

        header_top_row = QHBoxLayout()

        header_top_row.addWidget(app_title)

        header_top_row.addStretch()

        header_top_row.addWidget(self.add_members_button)

        header_top_row.addWidget(self.leave_group_button)

        header_top_row.addWidget(self.logout_button)

        self.chat_partner_label = QLabel(
            "Select a user to start chatting"
        )

        self.chat_partner_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 10pt;"
        )

        header_layout.addLayout(header_top_row)

        header_layout.addWidget(self.chat_partner_label)

        # Messages panel

        messages_panel = QFrame()

        messages_panel.setObjectName("Panel")

        messages_panel_layout = QVBoxLayout(messages_panel)

        messages_panel_layout.setContentsMargins(4, 4, 4, 4)

        self.messages = MessageWidget()

        messages_panel_layout.addWidget(self.messages)

        # Input bar

        self.input_bar = InputBar()

        self.input_bar.set_enabled(False)

        # Status bar

        self.status = StatusBarWidget()

        right_layout.addWidget(header)

        right_layout.addWidget(messages_panel, stretch=1)

        right_layout.addWidget(self.input_bar)

        right_layout.addWidget(self.status)

        root_layout.addWidget(left_panel, 1)

        root_layout.addLayout(right_layout, 3)

    # ==========================================================
    # Initialization
    # ==========================================================

    def initialize_ui(self):

        self.status.set_connected(True)

        self.status.set_algorithm(
            self.session.key_manager.algorithm
        )

        self.status.set_username(
            self.session.get_username()
        )

    # ==========================================================
    # Signal Connections
    # ==========================================================

    def connect_signals(self):

        self.conversation_list.conversation_selected.connect(
            self.open_conversation
        )

        self.input_bar.message_sent.connect(
            self.send_message
        )

        self.input_bar.attachment_selected.connect(
            self.handle_attachment_selected
        )

    # ==========================================================
    # Backend Callbacks
    # ==========================================================

    def register_callbacks(self):

        # ConversationStore (client/conversation_store.py) is the
        # single source of truth for sidebar state -- it already
        # reacts to session.users_updated internally (see
        # ClientSession.handle_user_list()), so this window only ever
        # needs to listen for conversations_changed, never
        # users_updated directly.
        self.session.conversation_store.conversations_changed.connect(
            self.render_conversations
        )

        self.session.message_received.connect(
            self.receive_message
        )

        # payload_message_received carries binary content (Phase 8 --
        # File & Image Transfer) that message_received's fixed
        # Signal(str, str, str) cannot -- see ClientSession's
        # declaration for why this is a separate signal rather than a
        # change to the existing one.
        self.session.payload_message_received.connect(
            self.receive_payload_message
        )

        # connection_changed carries only True/False (client/session.py
        # emits it on successful connect(), on explicit disconnect(),
        # and -- the gap this closes -- on an unexpected mid-session
        # drop detected by the receiver thread, client/receiver.py).
        # StatusBarWidget.set_connected() already takes exactly that
        # bool, so this is a direct connection: no new connection-state
        # concept, no polling, no second source of truth.
        self.session.connection_changed.connect(
            self.status.set_connected
        )

        self.session.error_occurred.connect(
            self.show_error
        )

        # C2 -- Read Receipts: a live "someone read up to now" hint
        # for whichever conversation is currently open -- see
        # handle_read_receipt_updated(). The authoritative status is
        # always re-derived from the database at load_history() time
        # regardless, so this is purely a same-session UI refresh.
        self.session.read_receipt_updated.connect(
            self.handle_read_receipt_updated
        )

        # -----------------------------------------
        # Sync UI with current session state
        # -----------------------------------------

        self.session.load_conversations()

    def render_conversations(self):
        """
        Re-render the sidebar from ConversationStore -- the single
        source of truth for conversation state. This is the only
        place the sidebar widget is populated; nothing else in this
        class (or anywhere else) mutates it directly.
        """

        summaries = self.session.conversation_store.get_all()

        self.conversation_list.render(summaries)

        for summary in summaries:

            self.conversation_list.set_unread_count(
                summary.key,
                self.session.get_unread_count(summary.key)
            )

    # ==========================================================
    # Events
    # ==========================================================

    def handle_find_user(self):
        """
        Search for a user by their unique ID and, if found, open a
        direct conversation with them (Issue 3 fix -- User Must Be
        Searched By Unique ID). Reuses the exact same conversation-
        opening path a sidebar click already uses (open_conversation())
        -- a ConversationSummary built from the lookup result is
        indistinguishable to that method from one ConversationStore
        would have produced for an online user with no history yet
        (see ConversationStore.update_online_status()'s identical
        placeholder shape).
        """

        dialog = FindUserDialog(self.session, self)

        if dialog.exec() != QDialog.Accepted:
            return

        found = dialog.get_result()

        if found is None:
            return

        summary = ConversationSummary(
            conversation_id=None,
            username=found["username"],
            is_online=found["username"] in self.session.get_online_users(),
            latest_message=None,
        )

        self.open_conversation(summary)

    def handle_create_group(self):
        """
        Open the group-creation dialog and, if confirmed with a name
        and at least one member, ask the session to create it. The
        new group appears in the sidebar asynchronously, once the
        server confirms it (see ClientSession.handle_group_create_result())
        -- there is no optimistic local update here.
        """

        dialog = CreateGroupDialog(self.session.get_online_users(), self)

        if dialog.exec() == QDialog.Accepted:

            name, member_usernames = dialog.get_result()

            if name and member_usernames:
                self.session.create_group_conversation(name, member_usernames)

    def handle_add_members(self):
        """
        Add one or more users to the currently open group conversation
        (Issue 2 fix -- Add Members After Group Creation). Candidates
        are the currently online users minus whoever is already a
        participant (including this client itself) -- ConversationStore.
        get() is the read-only accessor added for exactly this lookup.
        No optimistic local update: the sidebar refreshes once the
        server confirms via ClientSession.handle_group_members_added().
        """

        if not self.session.current_chat_is_group:
            return

        conversation_id = self.session.get_current_chat()

        if conversation_id is None:
            return

        summary = self.session.conversation_store.get(conversation_id)

        existing_participants = set(summary.participants or []) if summary else set()
        existing_participants.add(self.session.get_username())

        candidates = [
            username for username in self.session.get_online_users()
            if username not in existing_participants
        ]

        if not candidates:

            QMessageBox.information(
                self,
                "Add Members",
                "No additional online users are available to add."
            )

            return

        dialog = AddMembersDialog(candidates, self)

        if dialog.exec() == QDialog.Accepted:

            selected = dialog.get_result()

            if selected:
                self.session.add_group_members(conversation_id, selected)

    def handle_leave_group(self):
        """
        Leave the currently open group conversation (Phase 7 -- Group
        Membership Management). A no-op if the open conversation isn't
        a group -- the button is only visible when it is, but this
        guards direct calls/races too. No optimistic local update:
        the sidebar/message panel update once the server confirms via
        ClientSession.handle_group_member_left() ->
        conversations_changed, the same path every other conversation-
        store change already goes through.
        """

        if not self.session.current_chat_is_group:
            return

        conversation_id = self.session.get_current_chat()

        if conversation_id is None:
            return

        self.session.leave_group_conversation(conversation_id)

    def open_conversation(self, summary):
        """
        Open a conversation -- direct or group. ``summary`` is the
        whole ConversationSummary the sidebar row was rendered from
        (see ConversationListWidget.conversation_selected); passed to
        the session as-is (Phase 5 -- Secure Group Key Distribution)
        so it can resolve the real conversation_id via
        ConversationStore without ClientSession ever needing a bare
        key guessed at here. ``summary.key`` remains the addressing
        identity for everything else in this method (unread counts,
        history loading) -- unchanged since Phase 4.
        """

        key = summary.key

        self.session.set_current_chat(summary)

        # C2 -- Read Receipts: any reader accumulated for whatever
        # conversation was open before is now stale -- bubbles are
        # about to be fully re-rendered from fresh history below,
        # already reflecting current status.
        self._read_receipt_readers = set()

        self.session.clear_unread(key)

        self.render_conversations()

        self.leave_group_button.setVisible(summary.is_group)

        self.add_members_button.setVisible(summary.is_group)

        display_name = summary.group_name if summary.is_group else summary.username

        label = (
            f"Group: {display_name}" if summary.is_group
            else f"Chatting with {display_name}"
        )

        self.chat_partner_label.setText(label)

        self.input_bar.set_enabled(True)

        self.input_bar.focus_input()

        self.messages.clear_messages()

        self.messages.add_system_message(label)

        self.load_history(key, summary.is_group)

        # C2 -- Read Receipts: tell the server everything in this
        # conversation is now read -- only once the user has actually
        # opened it and its history has been loaded/rendered above,
        # never merely because the client reconnected or logged in.
        try:

            self.session.mark_conversation_read(self.session.current_conversation_id)

        except Exception as error:  # noqa: BLE001

            # Intentionally broad, matching send_message()'s/
            # handle_attachment_selected()'s outbound-failure pattern:
            # mark_conversation_read() can fail for reasons spanning
            # unrelated exception hierarchies (a socket-level OSError,
            # or anything session-state related), and the conversation
            # has already fully opened and rendered above -- a failure
            # here only means the read receipt itself didn't go out;
            # it must never block or undo the open.
            self.show_error(str(error))

    def load_history(self, key, is_group=False):
        """
        Populate the message panel with this conversation's stored
        history. Runs once per conversation open, right after the
        panel is cleared -- live messages continue to arrive and
        append via the unchanged receive_message()/send_message()
        paths after this returns.
        """

        history = self.session.load_conversation_history(key, is_group=is_group)

        for entry in history:

            timestamp = entry["timestamp"]

            timestamp_text = (
                timestamp.strftime("%H:%M") if timestamp else None
            )

            payload_type = entry.get("payload_type", PayloadType.TEXT)

            # C2 -- Read Receipts: message_id/read_status are only
            # ever meaningful for entry["is_own"] rows (see
            # ClientSession.load_conversation_history()'s docstring);
            # read_status is already None for a received row, so
            # passing it through unconditionally is safe -- the bubble
            # classes only ever render it for kind="sent" regardless.
            message_id = entry.get("message_id")
            read_status = entry.get("read_status")

            if payload_type == PayloadType.TEXT:

                if entry["is_own"]:

                    self.messages.add_sent_message(
                        entry["text"],
                        timestamp=timestamp_text,
                        message_id=message_id,
                        read_status=read_status,
                    )

                else:

                    self.messages.add_received_message(
                        entry["sender"],
                        entry["text"],
                        timestamp=timestamp_text
                    )

                continue

            content = entry.get("content")
            content_metadata = entry.get("content_metadata") or {}

            if content is None:

                # This client never received the epoch's key, or the
                # blob is missing -- mirror the existing undecryptable-
                # text placeholder rather than silently skipping it.
                placeholder = "[Attachment unavailable]"

                if entry["is_own"]:
                    self.messages.add_sent_message(
                        placeholder,
                        timestamp=timestamp_text,
                        message_id=message_id,
                        read_status=read_status,
                    )
                else:
                    self.messages.add_received_message(
                        entry["sender"], placeholder, timestamp=timestamp_text
                    )

                continue

            if payload_type == PayloadType.IMAGE:

                if entry["is_own"]:
                    self.messages.add_sent_image(
                        content,
                        timestamp=timestamp_text,
                        message_id=message_id,
                        read_status=read_status,
                    )
                else:
                    self.messages.add_received_image(
                        entry["sender"], content, timestamp=timestamp_text
                    )

            else:

                if entry["is_own"]:
                    self.messages.add_sent_file(
                        content,
                        content_metadata,
                        timestamp=timestamp_text,
                        message_id=message_id,
                        read_status=read_status,
                    )
                else:
                    self.messages.add_received_file(
                        entry["sender"], content, content_metadata, timestamp=timestamp_text
                    )

    def send_message(self, message):

        if self.session.get_current_chat() is None:

            QMessageBox.warning(
                self,
                "No User Selected",
                "Please select an online user."
            )

            return

        try:

            self.session.send_chat_message(message)

            self.messages.add_sent_message(
                message
            )

        except Exception as error:

            self.show_error(str(error))

    def handle_attachment_selected(self, file_path):
        """
        Send a locally-picked file/image as the next message in the
        open conversation (Phase 8 -- File & Image Transfer).
        Classification (IMAGE vs. FILE) happens inside
        ClientSession.send_attachment() -- this method never decides
        it. Renders the local "sent" bubble from the same bytes
        send_attachment() already read, rather than reading the file
        a second time.
        """

        if self.session.get_current_chat() is None:

            QMessageBox.warning(
                self,
                "No User Selected",
                "Please select a conversation."
            )

            return

        try:

            payload_type, content, content_metadata = (
                self.session.send_attachment(file_path)
            )

        except (OSError, ValueError) as error:

            self.show_error(str(error))

            return

        if payload_type == PayloadType.IMAGE:
            self.messages.add_sent_image(content)
        else:
            self.messages.add_sent_file(content, content_metadata)

    def receive_message(self, conversation_key, sender, message):
        """
        ``conversation_key`` identifies which conversation this
        belongs to (a username for direct, a conversation_id for
        group -- see ClientSession.handle_chat()); ``sender`` is
        always the individual who wrote it, used only for display.
        For a direct message the two are the same value, so this
        check behaves exactly as it did before Phase 4.
        """

        if sender == "system":

            self.messages.add_system_message(
                message
            )

            return

        if conversation_key != self.session.get_current_chat():

            # This message belongs to a different conversation. It is
            # already correctly persisted and will be shown when that
            # conversation is opened -- the currently open conversation
            # must stay completely unchanged. Track it as unread
            # instead, then re-render through the single sidebar
            # render path (ConversationStore already recorded this
            # message's preview via ClientSession.handle_chat()).
            self.session.increment_unread(conversation_key)

            self.render_conversations()

            return

        self.messages.add_received_message(
            sender,
            message
        )

    def receive_payload_message(
        self, conversation_key, sender, payload_type, content, content_metadata
    ):
        """
        Display a received file/image (Phase 8 -- File & Image
        Transfer). Mirrors receive_message()'s unread/current-
        conversation handling exactly -- the two differ only in what
        they hand to MessageWidget at the end, since binary content
        cannot flow through message_received (see ClientSession's
        payload_message_received declaration).
        """

        if conversation_key != self.session.get_current_chat():

            self.session.increment_unread(conversation_key)

            self.render_conversations()

            return

        if payload_type == PayloadType.IMAGE:
            self.messages.add_received_image(sender, content)
        else:
            self.messages.add_received_file(sender, content, content_metadata)

    def handle_read_receipt_updated(self, conversation_id, reader):
        """
        A live "someone read up to now" hint arrived (C2 -- Read
        Receipts). Ignored if it's not for the conversation currently
        on screen -- compared against current_conversation_id (the
        real conversation_id ClientSession.set_current_chat() already
        resolves), not get_current_chat() (which is a partner
        *username* for a direct conversation, not its conversation_id).

        Direct: the one other party has, by definition, just read
        every message they could see -- flip every sent bubble
        immediately. Group: accumulate readers and only flip once
        every currently-active participant (ConversationStore's own
        already-left-member-excluded list -- see
        ConversationStore.update_group_participants()) has been
        accounted for, per your "double-check only when all active
        recipients have read" decision. A departed member is simply
        never in that list, so they can never block it.
        """

        if conversation_id != self.session.current_conversation_id:
            return

        self._read_receipt_readers.add(reader)

        if not self.session.current_chat_is_group:
            self.messages.mark_all_sent_read()
            return

        summary = self.session.conversation_store.get(conversation_id)

        active_participants = set(summary.participants or []) if summary else set()

        if active_participants and self._read_receipt_readers.issuperset(active_participants):
            self.messages.mark_all_sent_read()

    def show_error(self, message):

        QMessageBox.critical(
            self,
            "Error",
            message
        )