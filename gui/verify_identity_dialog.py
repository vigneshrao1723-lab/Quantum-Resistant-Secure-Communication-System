"""
Verify Identity Dialog

Server-Untrusted Identity Verification, Stage 3: the one place this
application ever calls ClientSession.confirm_peer_verification() --
which itself is the only method that ever promotes a peer to
PEER_STATE_VERIFIED (see storage/secure_key_store.py::
verify_peer_fingerprint()). Presentation and user-confirmation control
only, per the Stage-3 design: every actual trust decision already
lives in ClientSession -- the fingerprint shown comes from
ClientSession.get_peer_fingerprint_for_verification(), and the only
thing this dialog can DO is call confirm_peer_verification(), once,
on an explicit confirming click, never automatically and never on
cancel.

Shared by all three states a peer can be in (UNVERIFIED,
PEER_KEY_STATE_CHANGED, or an already-VERIFIED peer opening this to
view/re-verify), differing only in which text is shown -- there is
exactly one verification action in this application, not three.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from client.session import PEER_KEY_STATE_CHANGED
from storage.secure_key_store import KeyStoreError, PEER_STATE_VERIFIED


class VerifyIdentityDialog(QDialog):
    """
    ``state`` is whatever ClientSession.get_peer_verification_state()
    returned for ``username`` at the moment this dialog was opened --
    PEER_STATE_UNVERIFIED, PEER_KEY_STATE_CHANGED, or PEER_STATE_VERIFIED
    (view/re-verify). The fingerprint shown is captured ONCE, at
    construction, and that exact same value is what gets passed to
    confirm_peer_verification() if the user confirms -- never
    re-fetched at confirm time, so what gets verified is always
    exactly what was displayed and compared, even if this peer's
    pending state changes again while the dialog happens to still be
    open.

    was_verified() reports whether this dialog actually promoted the
    peer to VERIFIED -- False for cancel or for simply closing the
    dialog without confirming.
    """

    def __init__(self, session, username, state, parent=None):
        super().__init__(parent)

        self.session = session
        self.username = username
        self.state = state
        self._verified = False

        self._fingerprint = session.get_peer_fingerprint_for_verification(
            username
        )

        self.setWindowTitle("Verify Identity")

        self.build_ui()

    # ==========================================================
    # UI
    # ==========================================================

    def build_ui(self):

        layout = QVBoxLayout(self)

        if self.state == PEER_KEY_STATE_CHANGED:

            warning = QLabel(
                f"This contact's security identity has changed."
            )
            warning.setWordWrap(True)
            warning.setStyleSheet(
                "font-weight: 700; color: #E5637E;"
            )
            layout.addWidget(warning)

            explanation = QLabel(
                f"The key now presented for {self.username} is "
                f"DIFFERENT from the one you previously verified. "
                f"This can mean {self.username} reinstalled the app or "
                f"switched devices -- or it can mean someone else is "
                f"attempting to impersonate them. Protected "
                f"communication with {self.username} is blocked until "
                f"you verify the new fingerprint below."
            )

        elif self.state == PEER_STATE_VERIFIED:

            heading = QLabel(f"{self.username} is verified.")
            heading.setStyleSheet("font-weight: 700;")
            layout.addWidget(heading)

            explanation = QLabel(
                f"You can re-verify {self.username}'s current "
                f"fingerprint below at any time."
            )

        else:

            heading = QLabel(f"{self.username}'s identity is not verified.")
            heading.setStyleSheet("font-weight: 700;")
            layout.addWidget(heading)

            explanation = QLabel(
                f"Secure messaging with {self.username} is unavailable "
                f"until you verify their identity."
            )

        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        instructions = QLabel(
            "Compare the fingerprint below with " + self.username +
            " through a channel this application does not control -- "
            "read it aloud on a call, compare it in person, or any "
            "channel other than this app itself. Only confirm if it "
            "matches exactly."
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        self.fingerprint_label = QLabel(
            self._fingerprint or "No key received for this contact yet."
        )
        self.fingerprint_label.setTextFormat(Qt.PlainText)
        self.fingerprint_label.setWordWrap(True)
        self.fingerprint_label.setStyleSheet(
            "font-family: monospace; font-size: 13px; font-weight: 700;"
        )
        layout.addWidget(self.fingerprint_label)

        self.confirm_button = QPushButton("Yes, This Matches -- Verify")
        self.confirm_button.setCursor(Qt.PointingHandCursor)
        self.confirm_button.setEnabled(self._fingerprint is not None)
        self.confirm_button.clicked.connect(self.handle_confirm)
        layout.addWidget(self.confirm_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("SecondaryButton")
        cancel_button.setCursor(Qt.PointingHandCursor)
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

    # ==========================================================
    # Events
    # ==========================================================

    def handle_confirm(self):

        if not self._fingerprint:
            return

        try:
            self.session.confirm_peer_verification(
                self.username, self._fingerprint
            )
        except KeyStoreError as error:
            self.error_label.setText(str(error))
            return

        self._verified = True

        self.accept()

    # ==========================================================
    # Public Methods
    # ==========================================================

    def was_verified(self):
        """
        True only if this dialog's explicit confirm action actually
        ran ClientSession.confirm_peer_verification() successfully.
        """

        return self._verified
