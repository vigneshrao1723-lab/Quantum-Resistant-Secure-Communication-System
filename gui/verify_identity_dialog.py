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
from gui.styles import COLOR_DANGER, COLOR_PANEL_ALT
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

        # People are shown by display name (not unique); everything below that addresses or
        # verifies someone still uses the account handle, ``self.username``.
        lookup = getattr(session, "display_name_for", None)
        try:
            shown = lookup(username) if lookup else None
        except Exception:  # noqa: BLE001
            shown = None
        self.name = shown if isinstance(shown, str) and shown else username

        self._fingerprint = session.get_peer_fingerprint_for_verification(
            username
        )

        self.setWindowTitle("Verify Identity")

        # Wide enough that the 16 fingerprint groups sit on two even rows.
        self.setMinimumWidth(470)

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
                f"font-weight: 700; color: {COLOR_DANGER};"
            )
            layout.addWidget(warning)

            explanation = QLabel(
                f"The key now presented for {self.name} is "
                f"DIFFERENT from the one you previously verified. "
                f"This can mean {self.name} reinstalled the app or "
                f"switched devices -- or it can mean someone else is "
                f"attempting to impersonate them. Protected "
                f"communication with {self.name} is blocked until "
                f"you verify the new fingerprint below."
            )

        elif self.state == PEER_STATE_VERIFIED:

            heading = QLabel(f"{self.name} is verified.")
            heading.setStyleSheet("font-weight: 700;")
            layout.addWidget(heading)

            explanation = QLabel(
                f"You can re-verify {self.name}'s current "
                f"fingerprint below at any time."
            )

        else:

            heading = QLabel(f"{self.name}'s identity is not verified.")
            heading.setStyleSheet("font-weight: 700;")
            layout.addWidget(heading)

            explanation = QLabel(
                f"Secure messaging with {self.name} is unavailable "
                f"until you verify their identity."
            )

        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        instructions = QLabel(
            "Compare the fingerprint below with " + self.name +
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
        # The one thing this dialog asks a person to compare by eye, so it
        # gets a real fixed-width face (the bare ``monospace`` family does
        # not resolve to one on Windows, which left it in the UI font) in a
        # quiet inset panel, and can be selected for copying.
        self.fingerprint_label.setObjectName("Fingerprint")
        self.fingerprint_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.fingerprint_label.setStyleSheet(
            '#Fingerprint { font-family: "Cascadia Mono", "Consolas", '
            '"Courier New", monospace; font-size: 11pt; font-weight: 600; '
            f"padding: 10px 12px; border-radius: 10px; background: {COLOR_PANEL_ALT}; }}"
        )
        layout.addWidget(self.fingerprint_label)

        # Your own number is what the other person compares THEIR screen against. It is not shown
        # until asked for: it lives here, next to the comparison it is for, rather than as a
        # standing panel in Settings.
        self.show_own_button = QPushButton("Show my safety number")
        self.show_own_button.setObjectName("SecondaryButton")
        self.show_own_button.setCursor(Qt.PointingHandCursor)
        self.show_own_button.clicked.connect(self._toggle_own_number)
        layout.addWidget(self.show_own_button)

        self.own_number_hint = QLabel(
            f"Read this to {self.name} when they verify you. It should match the number their "
            "app shows for you."
        )
        self.own_number_hint.setWordWrap(True)
        self.own_number_hint.setVisible(False)
        layout.addWidget(self.own_number_hint)

        own = self.session.get_own_fingerprint()
        self.own_fingerprint_label = QLabel(own if isinstance(own, str) and own else "Not available yet.")
        self.own_fingerprint_label.setObjectName("OwnSafetyNumber")
        self.own_fingerprint_label.setTextFormat(Qt.PlainText)
        self.own_fingerprint_label.setWordWrap(True)
        self.own_fingerprint_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.own_fingerprint_label.setStyleSheet(
            '#OwnSafetyNumber { font-family: "Cascadia Mono", "Consolas", '
            '"Courier New", monospace; font-size: 11pt; font-weight: 600; '
            f"padding: 10px 12px; border-radius: 10px; background: {COLOR_PANEL_ALT}; }}"
        )
        self.own_fingerprint_label.setVisible(False)
        layout.addWidget(self.own_fingerprint_label)

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

    def _toggle_own_number(self, _checked=False):
        # A plain button (not a checkable one) so assistive technology and UI automation can press it.
        shown = self.own_fingerprint_label.isHidden()
        self.show_own_button.setText("Hide my safety number" if shown else "Show my safety number")
        self.own_number_hint.setVisible(shown)
        self.own_fingerprint_label.setVisible(shown)
        self.adjustSize()

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
