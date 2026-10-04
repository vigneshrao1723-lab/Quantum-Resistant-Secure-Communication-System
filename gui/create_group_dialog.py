"""
Create Group Dialog

Minimal group-creation UI: a name field and a checkable list of
currently online users. Phase 4 (Secure Group Messaging Foundation)
fixes membership at creation time -- no invitations, join links, or
post-creation membership changes.
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


class CreateGroupDialog(QDialog):
    """
    Collects a group name and a member selection from the currently
    online users, plus (UI Finalization Decision 2) anyone found by
    phone number regardless of presence -- a group's membership is
    fixed at creation (see module docstring), so a candidate found
    offline is exactly as valid a choice as one who happens to be
    online right now. get_result() returns (name, [selected_usernames])
    for the caller to hand to ClientSession.create_group_conversation().
    """

    def __init__(self, session, online_users, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Create Group")

        self.build_ui(online_users)

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self, online_users):

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Group name"))

        self.name_input = QLineEdit()

        self.name_input.setPlaceholderText("Enter a group name")

        layout.addWidget(self.name_input)

        layout.addWidget(QLabel("Members (online users)"))

        # UI Finalization Decision 2 -- find and add someone by phone
        # number, online or not, reusing FindUserDialog's exact lookup
        # (session.find_user_by_phone_number()) rather than a new
        # server capability. A successful search APPENDS a new
        # checkable row to the list below; it does not replace it or
        # filter it -- the online-user rows built below stay exactly
        # as they are.
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
        # L-1: search_status_label's text is set from
        # _handle_add_by_phone() below, either this module's own fixed
        # strings or a looked-up display_name/username straight from
        # the server -- never markup.
        self.search_status_label.setTextFormat(Qt.PlainText)
        self.search_status_label.setWordWrap(True)
        layout.addWidget(self.search_status_label)

        self.member_list = QListWidget()

        # Bug fix (real-application testing): QListWidget's default
        # selectionMode is SingleSelection, which only highlights the
        # clicked row -- it does not toggle ItemIsUserCheckable's
        # checkbox unless the user clicks the small checkbox glyph
        # exactly. That made multi-member selection look broken (only
        # whichever checkbox was hit dead-on ever got checked; every
        # other click just moved the highlight). NoSelection removes
        # the misleading highlight entirely -- the checkbox state is
        # the only selection mechanism now, toggled by clicking
        # anywhere on the row via _toggle_item_check_state() below.
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

        for username in online_users:
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
        """
        Toggle a member row's checkbox on click anywhere in the row --
        the fix for the multi-member selection bug (see build_ui()).
        Every checked row survives independently; clicking one member
        never affects another's check state.
        """

        item.setCheckState(
            Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
        )

    def _handle_add_by_phone(self):
        """
        Look up the entered phone number and, if found, append it as a
        new unchecked row (UI Finalization Decision 2) -- the user
        still has to check it, exactly like an online row, rather than
        this method deciding membership on its own.

        Reuses ClientSession.find_user_by_phone_number() unchanged --
        no new server capability. Guards mirror
        FindUserDialog.handle_search()'s: reject a lookup of your own
        number, and (new here, since this list can grow across
        multiple searches) reject a number already present in the
        list rather than adding a second row for the same user.
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
        row-construction path for both the initial online-users list
        (build_ui()) and a phone-search result
        (_handle_add_by_phone()), so the two can never drift in
        behavior.
        """

        item = QListWidgetItem(username)

        # ItemIsUserCheckable is deliberately CLEARED, not set.
        #
        # With it set, Qt toggles the checkbox itself whenever the
        # small indicator glyph is clicked and THEN emits itemClicked
        # -- so _toggle_item_check_state() below toggled a second time
        # and cancelled the click. Measured with real mouse events:
        # clicking the indicator selected nothing at all, while
        # clicking the row text worked, so a user ticking boxes ended
        # up with an empty or partial member list.
        #
        # Clearing the flag leaves _toggle_item_check_state() as the
        # single toggle path for a click anywhere on the row,
        # indicator included. The checkbox still renders, because that
        # is driven by setCheckState() below, not by this flag.
        item.setFlags(item.flags() & ~Qt.ItemIsUserCheckable)

        item.setCheckState(Qt.Unchecked)

        self.member_list.addItem(item)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def get_result(self):
        """
        Returns (name, [selected_usernames]).
        """

        name = self.name_input.text().strip()

        selected = []

        for i in range(self.member_list.count()):

            item = self.member_list.item(i)

            if item.checkState() == Qt.Checked:
                selected.append(item.text())

        return name, selected
