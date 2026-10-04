"""
Add Members Dialog

Minimal "add members to an existing group" UI (Issue 2 fix -- Add
Members After Group Creation): a checkable list of online users who
are not already in the group. Mirrors gui/create_group_dialog.py's
member-picker exactly, including its click-to-toggle checkbox fix --
duplicated rather than shared, matching this codebase's established
per-file convention (see e.g. the repeated _utc_now() helper across
repository files) for two call sites this small.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)


class AddMembersDialog(QDialog):
    """
    Collects a member selection from the given candidate usernames
    (already filtered by the caller to exclude existing participants
    and self), plus (UI Finalization Decision 2) anyone found by phone
    number regardless of presence -- see CreateGroupDialog's identical
    rationale. get_result() returns [selected_usernames] for the
    caller to hand to ClientSession.add_group_members().
    """

    def __init__(self, session, candidate_usernames, existing_participant_usernames, parent=None):
        super().__init__(parent)

        self.session = session

        # candidate_usernames is who CAN be added (already
        # online-and-not-a-member, filtered by the caller);
        # existing_participant_usernames -- already includes this
        # client's own username, per ChatWindow.handle_add_members()
        # -- is who a phone search must refuse to add again, since
        # those never appear as a row at all (unlike a duplicate
        # online candidate, which _member_row_index() below already
        # catches by simply being a row).
        self._existing_participant_usernames = set(existing_participant_usernames)

        self.setWindowTitle("Add Members")

        self.build_ui(candidate_usernames)

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self, candidate_usernames):

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Add members (online users)"))

        # UI Finalization Decision 2 -- see
        # gui/create_group_dialog.py::build_ui()'s identical block for
        # the full rationale (same lookup, same append-not-replace
        # behavior, offline allowed).
        search_row = QHBoxLayout()

        self.phone_search_input = QLineEdit()
        self.phone_search_input.setPlaceholderText(
            "Add by phone number, e.g. +91 98765 43210"
        )
        self.phone_search_input.returnPressed.connect(
            self._handle_add_by_phone
        )
        search_row.addWidget(self.phone_search_input)

        add_button = QPushButton("Add")
        add_button.setCursor(Qt.PointingHandCursor)
        add_button.clicked.connect(self._handle_add_by_phone)
        search_row.addWidget(add_button)

        layout.addLayout(search_row)

        self.search_status_label = QLabel("")
        # L-1: see create_group_dialog.py's identical label -- never
        # markup.
        self.search_status_label.setTextFormat(Qt.PlainText)
        self.search_status_label.setWordWrap(True)
        layout.addWidget(self.search_status_label)

        self.member_list = QListWidget()

        # See gui/create_group_dialog.py::build_ui()'s docstring for
        # why NoSelection + itemClicked-toggles-checkbox is required
        # here, not just SingleSelection's default highlight-only
        # click behavior.
        self.member_list.setSelectionMode(QAbstractItemView.NoSelection)

        # The toggle LOGIC above was correct, but the checkbox was
        # still hard to use: the default indicator is a small,
        # low-contrast glyph on this dark palette, and the row had no
        # padding, so the thing a user aims at was both faint and
        # cramped. "MemberList" scopes the indicator/padding rules in
        # gui/styles.py to the member pickers -- the conversation
        # sidebar uses setItemWidget rows whose geometry must not
        # change.
        self.member_list.setObjectName("MemberList")

        for username in candidate_usernames:
            self._add_member_row(username)

        self.member_list.itemClicked.connect(
            self._toggle_item_check_state
        )

        layout.addWidget(self.member_list)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )

        buttons.accepted.connect(self.accept)

        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    # ==========================================================
    # Events
    # ==========================================================

    def _toggle_item_check_state(self, item):

        item.setCheckState(
            Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
        )

    def _handle_add_by_phone(self):
        """
        See gui/create_group_dialog.py::_handle_add_by_phone() for the
        full rationale -- identical lookup and append behavior. The
        one difference: this dialog also rejects a number belonging to
        an EXISTING group participant (self._existing_participant_usernames),
        not just a duplicate row, since an existing member is never
        shown as a candidate row to begin with.
        """

        phone_number = self.phone_search_input.text().strip()

        if not phone_number:
            return

        try:
            result = self.session.find_user_by_phone_number(phone_number)
        except PermissionError as error:
            self.search_status_label.setText(str(error))
            return

        if result is None:
            self.search_status_label.setText(
                "No user is registered with that phone number."
            )
            return

        username = result["username"]

        if username == self.session.get_username():
            self.search_status_label.setText("That is your own account.")
            return

        if username in self._existing_participant_usernames:
            self.search_status_label.setText(
                f"{result['display_name']} (@{username}) is already in this group."
            )
            return

        if self._member_row_index(username) is not None:
            self.search_status_label.setText(
                f"{result['display_name']} (@{username}) is already in this list."
            )
            return

        self._add_member_row(username)

        self.search_status_label.setText(
            f"Added {result['display_name']} (@{username}) -- check the box below to include them."
        )

        self.phone_search_input.clear()

    # ==========================================================
    # Internal Helpers
    # ==========================================================

    def _member_row_index(self, username):
        """Row index for ``username`` in member_list, or None."""

        for i in range(self.member_list.count()):
            if self.member_list.item(i).text() == username:
                return i

        return None

    def _add_member_row(self, username):
        """
        Append one unchecked, click-to-toggle member row. The single
        row-construction path for both the initial candidate list
        (build_ui()) and a phone-search result
        (_handle_add_by_phone()), so the two can never drift in
        behavior.
        """

        item = QListWidgetItem(username)

        # Cleared, not set -- see gui/create_group_dialog.py's
        # identical line for the full rationale: with the flag set,
        # Qt toggles the indicator itself and then emits itemClicked,
        # so _toggle_item_check_state() cancelled the click. Clearing
        # it makes that handler the single toggle path for a click
        # anywhere on the row.
        item.setFlags(item.flags() & ~Qt.ItemIsUserCheckable)

        item.setCheckState(Qt.Unchecked)

        self.member_list.addItem(item)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def get_result(self):
        """
        Returns [selected_usernames].
        """

        selected = []

        for i in range(self.member_list.count()):

            item = self.member_list.item(i)

            if item.checkState() == Qt.Checked:
                selected.append(item.text())

        return selected
