"""
Find User Dialog

Search-by-unique-ID UI (Issue 3 fix -- User Must Be Searched By
Unique ID): a user must be looked up by their unique ID before a
conversation can be opened with them -- no unrestricted list, no
immediate chat. Shows only the found user's username/display name,
never email or any other field.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


class FindUserDialog(QDialog):
    """
    Looks up a user by unique ID via ClientSession.find_user_by_id().
    get_result() returns the found {"user_id", "username",
    "display_name"} dict, or None if the dialog was cancelled/never
    found anyone.
    """

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session
        self._found = None

        self.setWindowTitle("Find User")

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Phone Number"))

        hint = QLabel(
            "Find someone by the phone number they registered with. "
            "They can find you by yours, shown in the status bar."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.id_input = QLineEdit()

        self.id_input.setPlaceholderText("e.g. +91 98765 43210")

        self.id_input.returnPressed.connect(
            self.handle_search
        )

        layout.addWidget(self.id_input)

        self.search_button = QPushButton("Search")

        self.search_button.setCursor(Qt.PointingHandCursor)

        self.search_button.clicked.connect(
            self.handle_search
        )

        layout.addWidget(self.search_button)

        self.result_label = QLabel("")

        # L-1: handle_search() writes a looked-up display_name and
        # username into this label, straight from the server.
        self.result_label.setTextFormat(Qt.PlainText)

        self.result_label.setWordWrap(True)

        layout.addWidget(self.result_label)

        self.open_button = QPushButton("Open Chat")

        self.open_button.setEnabled(False)

        self.open_button.setCursor(Qt.PointingHandCursor)

        self.open_button.clicked.connect(
            self.accept
        )

        layout.addWidget(self.open_button)

        cancel_button = QPushButton("Cancel")

        cancel_button.setObjectName("SecondaryButton")

        cancel_button.setCursor(Qt.PointingHandCursor)

        cancel_button.clicked.connect(
            self.reject
        )

        layout.addWidget(cancel_button)

    # ==========================================================
    # Events
    # ==========================================================

    def handle_search(self):

        phone_number = self.id_input.text().strip()

        if not phone_number:
            return

        self._found = None

        self.open_button.setEnabled(False)

        try:
            result = self.session.find_user_by_phone_number(phone_number)
        except PermissionError as error:
            self.result_label.setText(str(error))
            return

        if result is None:
            self.result_label.setText(
                "No user is registered with that phone number."
            )
            return

        if result["username"] == self.session.get_username():
            self.result_label.setText("That is your own account.")
            return

        self._found = result

        self.result_label.setText(
            f"Found: {result['display_name']} (@{result['username']})"
        )

        self.open_button.setEnabled(True)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def get_result(self):
        """
        Returns the found user dict, or None.
        """

        return self._found
