"""
Status Bar Widget

Displays the current connection status,
active encryption algorithm, and logged-in user.
"""

from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QHBoxLayout,
)

from gui.styles import (
    COLOR_ONLINE,
    COLOR_OFFLINE,
    COLOR_QUANTUM,
    COLOR_CLASSICAL,
    COLOR_PANEL_ALT,
    COLOR_TEXT_MUTED,
)


class StatusBarWidget(QWidget):
    """
    Status bar displayed at the bottom
    of the chat window.
    """

    def __init__(self):
        super().__init__()

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 6, 4, 6)

        self.connection_label = QLabel(
            f"● Disconnected"
        )
        self.connection_label.setStyleSheet(
            f"color: {COLOR_OFFLINE}; font-weight: 600; font-size: 9.5pt;"
        )

        self.algorithm_label = QLabel(
            "Encryption: —"
        )
        self.algorithm_label.setStyleSheet(
            f"background-color: {COLOR_PANEL_ALT}; "
            "padding: 4px 12px; border-radius: 10px; "
            "font-size: 9pt; font-weight: 600;"
        )

        # BUG 7 -- the user's own discovery identifier, shown so it
        # can be shared. Populated by ChatWindow.initialize_ui().
        self.phone_label = QLabel("")
        self.phone_label.setObjectName("StatusPhone")

        self.user_label = QLabel(
            "User: -"
        )
        self.user_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;"
        )

        layout.addWidget(self.connection_label)

        layout.addStretch()

        layout.addWidget(self.algorithm_label)

        layout.addSpacing(20)

        layout.addWidget(self.phone_label)

        layout.addWidget(self.user_label)

    # ==========================================================
    # Public Methods
    # ==========================================================

    def set_connected(self, connected):
        """
        Update the connection status.
        """

        if connected:
            self.connection_label.setText("● Connected")
            self.connection_label.setStyleSheet(
                f"color: {COLOR_ONLINE}; font-weight: 600; font-size: 9.5pt;"
            )
        else:
            self.connection_label.setText("● Disconnected")
            self.connection_label.setStyleSheet(
                f"color: {COLOR_OFFLINE}; font-weight: 600; font-size: 9.5pt;"
            )

    def set_algorithm(self, algorithm):
        """
        Update the encryption algorithm badge.

        Kyber (post-quantum) is highlighted in teal,
        RSA (classical) in amber, so the currently
        active mode is obvious at a glance.
        """

        algorithm = (algorithm or "").upper()

        if algorithm == "KYBER":

            label = "🛡 Kyber (Post-Quantum)"
            color = COLOR_QUANTUM

        elif algorithm == "RSA":

            label = "🔑 RSA (Classical)"
            color = COLOR_CLASSICAL

        else:

            label = f"Encryption: {algorithm or '—'}"
            color = COLOR_TEXT_MUTED

        self.algorithm_label.setText(label)

        self.algorithm_label.setStyleSheet(
            f"background-color: {COLOR_PANEL_ALT}; color: {color}; "
            "padding: 4px 12px; border-radius: 10px; "
            "font-size: 9pt; font-weight: 600;"
        )

    def set_phone_number(self, phone_number):
        """
        Show the signed-in user's own phone number (BUG 7).

        This is the identifier other people search by, so its owner
        has to be able to read it off their own screen to share it --
        the previous identifier was the internal UUID, which the
        application never displayed, leaving no way to be found.
        Nothing else about the account is exposed here.
        """

        self.phone_label.setText(
            f"☎ {phone_number}" if phone_number else ""
        )

    def set_username(self, username):
        """
        Update the logged-in username.
        """

        self.user_label.setText(
            f"User: {username}"
        )