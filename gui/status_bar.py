"""
Status Bar Widget

Displays the current connection status,
active encryption algorithm, and logged-in user.
"""

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QHBoxLayout,
)

from gui.styles import (
    COLOR_ONLINE,
    COLOR_OFFLINE,
    COLOR_DANGER,
    COLOR_QUANTUM,
    COLOR_CLASSICAL,
    COLOR_PANEL_ALT,
    COLOR_TEXT_MUTED,
)

# Phase 14.1 -- Security Rejection GUI: how long a security notice stays
# visible before clearing itself. Self-clearing (rather than requiring
# a dismiss click) is deliberate -- see StatusBarWidget.set_security_
# notice()'s own docstring for why a malicious packet must not be able
# to pile up interruptions.
SECURITY_NOTICE_DURATION_MS = 6000


class StatusBarWidget(QWidget):
    """
    Status bar displayed at the bottom
    of the chat window.
    """

    def __init__(self):
        super().__init__()

        self.build_ui()

        # Phase 14.1 -- Security Rejection GUI: a single-shot timer that
        # clears the security notice on its own, so a rapid sequence of
        # rejected packets (e.g. a malicious server retrying) replaces
        # the same label and resets the same timer rather than queuing
        # up separate, stacking interruptions.
        self._security_notice_timer = QTimer(self)
        self._security_notice_timer.setSingleShot(True)
        self._security_notice_timer.timeout.connect(self._clear_security_notice)

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 6, 4, 6)

        self.connection_label = QLabel(
            f"● Disconnected"
        )
        self.connection_label.setTextFormat(Qt.PlainText)
        self.connection_label.setStyleSheet(
            f"color: {COLOR_OFFLINE}; font-weight: 600; font-size: 9.5pt;"
        )

        self.algorithm_label = QLabel(
            "Encryption: —"
        )
        self.algorithm_label.setTextFormat(Qt.PlainText)
        self.algorithm_label.setStyleSheet(
            f"background-color: {COLOR_PANEL_ALT}; "
            "padding: 4px 12px; border-radius: 10px; "
            "font-size: 9pt; font-weight: 600;"
        )

        # BUG 7 -- the user's own discovery identifier, shown so it
        # can be shared. Populated by ChatWindow.initialize_ui().
        self.phone_label = QLabel("")
        # L-1: both of these are filled from server-supplied account
        # fields (own phone number, own username).
        self.phone_label.setTextFormat(Qt.PlainText)
        self.phone_label.setObjectName("StatusPhone")

        self.user_label = QLabel(
            "User: -"
        )
        self.user_label.setTextFormat(Qt.PlainText)
        self.user_label.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 9.5pt;"
        )

        # Phase 14.1 -- Security Rejection GUI: empty/hidden until a
        # rejection actually happens (set_security_notice()) -- takes
        # no permanent space in the bar otherwise.
        self.security_label = QLabel("")
        self.security_label.setTextFormat(Qt.PlainText)
        self.security_label.setStyleSheet(
            f"color: {COLOR_DANGER}; font-weight: 600; font-size: 9pt;"
        )
        self.security_label.setVisible(False)

        layout.addWidget(self.connection_label)

        layout.addWidget(self.security_label)

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

    def set_security_notice(self, text):
        """
        Phase 14.1 -- Security Rejection GUI: show a brief, non-blocking
        security notice (e.g. "a security-sensitive packet was
        rejected") and auto-clear it after SECURITY_NOTICE_DURATION_MS.

        Deliberately NOT a QMessageBox: a forged/rejected packet is,
        by construction, something ClientSession has already handled
        safely (see ClientSession.security_rejection's own docstring --
        no trusted key or identity state is ever altered by the
        rejection itself). A modal dialog would let a malicious server
        repeatedly interrupt the user just by resending forged
        packets; a self-clearing status-bar line is noticeable without
        being a repeatable denial-of-service against the UI. Calling
        this again before the previous notice expired simply replaces
        the text and restarts the timer -- notices never queue or
        stack.

        ``text`` is caller-supplied and must already be a safe,
        human-readable string -- this method has no way to know
        whether it came from cryptographic material, so composing that
        text safely is entirely the caller's responsibility (see
        ChatWindow.handle_security_rejection()).
        """

        self.security_label.setText(text)
        self.security_label.setVisible(bool(text))
        self._security_notice_timer.start(SECURITY_NOTICE_DURATION_MS)

    def _clear_security_notice(self):
        self.security_label.setText("")
        self.security_label.setVisible(False)