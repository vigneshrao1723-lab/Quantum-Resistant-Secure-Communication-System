"""
Device Management Dialog (Phase 19.19 -- Desktop parity closure).

Backend + ClientSession support (enroll_device()/list_devices()/
authorize_device()/revoke_device(), all Phase 16/16B) already existed
and was already fully tested against a real server -- Desktop's GUI
never called any of it. This dialog is the missing surface, not a new
implementation of device management: every action below is a direct,
unmodified call to the existing session methods.

Authorization/revocation decisions are always re-derived server-side
(server/device_handler.py) from the caller's own bound, AUTHORIZED
device -- this dialog hiding a button for a state that would be
rejected anyway is a convenience, never the enforcement, exactly like
gui/group_info_dialog.py's identical posture for group admin actions.

Lazy self-enrollment: Desktop never called enroll_device()/
bind_device_session() anywhere before this phase, so a real user's
own running installation was never actually registered as a device at
all -- opening this dialog is what activates it for the first time
(persisted afterward via the existing SecureKeyStore device_id
mechanism, so it happens at most once per installation, matching
enroll_device()'s own docstring). This is a deliberately narrow,
opt-in trigger point -- it does not run automatically at login, so no
existing test or session that never opens this dialog is affected.
"""

import platform as platform_module

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.styles import COLOR_CLASSICAL, COLOR_DANGER, COLOR_ONLINE, COLOR_TEXT_MUTED
from storage.secure_key_store import PEER_STATE_VERIFIED

_STATE_COLORS = {
    "AUTHORIZED": COLOR_ONLINE,
    "PENDING": COLOR_CLASSICAL,
    "REVOKED": COLOR_DANGER,
}


class DeviceManagementDialog(QDialog):
    """Lists every device enrolled on this account, with an
    authorized-viewer-only Authorize/Revoke action per row."""

    def __init__(self, session, parent=None):
        super().__init__(parent)

        self.session = session

        self.setWindowTitle("Device Management")
        self.resize(480, 420)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)

        self._bound_while_authorized = False

        self._device_list = QListWidget()

        refresh_button = QPushButton("Refresh")
        refresh_button.setCursor(Qt.PointingHandCursor)
        refresh_button.clicked.connect(self._refresh)

        close_button = QPushButton("Close")
        close_button.setObjectName("SecondaryButton")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.clicked.connect(self.accept)

        button_row = QHBoxLayout()
        button_row.addWidget(refresh_button)
        button_row.addStretch()
        button_row.addWidget(close_button)

        own_number = self.session.get_own_fingerprint()
        self._own_number_label = QLabel(
            f"This device's safety number (read it to the other device when it asks you to compare):\n"
            f"{own_number or 'Not available yet.'}"
        )
        self._own_number_label.setWordWrap(True)
        self._own_number_label.setTextFormat(Qt.PlainText)
        self._own_number_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Devices enrolled on this account"))
        layout.addWidget(self._own_number_label)
        layout.addWidget(self._device_list)
        layout.addWidget(self._status_label)
        layout.addLayout(button_row)

        self._ensure_this_device_enrolled()
        self._refresh()

    # ==========================================================
    # Enrollment (lazy, once per installation)
    # ==========================================================

    def _ensure_this_device_enrolled(self):
        if self.session.device_id is not None:
            return

        self._status_label.setText("Enrolling this device...")

        try:
            device_name = platform_module.node() or "Desktop"
            result = self.session.enroll_device(device_name=device_name, platform="Desktop")
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(f"Could not enroll this device: {error}")
            return

        if not result.get("success"):
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(result.get("error") or "Could not enroll this device.")
            return

        try:
            self.session.bind_device_session()
        except Exception:  # noqa: BLE001
            # Best-effort -- device_session_bind only activates the
            # additional server-side revocation-enforcement check on
            # THIS connection (see server/client_handler.py's own
            # is_device_bound_and_authorized() docstring); enrollment
            # itself already succeeded above regardless.
            pass

        state = result.get("state")
        self._status_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        if state == "AUTHORIZED":
            self._status_label.setText("This device is enrolled and authorized (first device on this account).")
        else:
            self._status_label.setText(
                "This device is enrolled and PENDING -- authorize it from another already-authorized device."
            )

    # ==========================================================
    # List rendering
    # ==========================================================

    def _refresh(self):
        try:
            devices = self.session.list_devices()
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(f"Could not load device list: {error}")
            return

        own_device_id = self.session.device_id
        own_state = next(
            (d.get("state") for d in devices if d.get("device_id") == own_device_id), None
        )
        viewer_is_authorized = own_state == "AUTHORIZED"

        # Enrollment bound this connection while the device was still
        # PENDING; once another device authorizes it, bind again so the
        # server will relay key packages to it.
        if viewer_is_authorized and not self._bound_while_authorized:
            try:
                bind_result = self.session.bind_device_session()
            except Exception as error:  # noqa: BLE001
                bind_result = {"success": False, "error": str(error)}

            if bind_result.get("success"):
                self._bound_while_authorized = True
            else:
                self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
                self._status_label.setText(
                    bind_result.get("error") or "Could not bind this device to the connection."
                )

        self._device_list.clear()

        for device in devices:
            self._add_device_row(device, own_device_id, viewer_is_authorized)

    def _add_device_row(self, device, own_device_id, viewer_is_authorized):
        device_id = device.get("device_id") or ""
        state = device.get("state") or "PENDING"
        is_self = device_id == own_device_id

        row = QWidget()
        row_layout = QVBoxLayout(row)
        row_layout.setContentsMargins(6, 4, 6, 4)

        name = device.get("device_name") or "Unnamed device"
        platform_name = device.get("platform") or "Unknown platform"
        title = f"{name} ({platform_name})"
        if is_self:
            title += "  -- this device"

        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: 600;")
        row_layout.addWidget(title_label)

        # Human-friendly device identifier -- the full UUID is real
        # data (never fabricated), just shortened for readability; the
        # fingerprint itself is not shown here at all (it exists to be
        # compared out-of-band by whoever is about to authorize this
        # device, not displayed as a raw debug value on every row).
        short_id = device_id[:8] + "..." if len(device_id) > 8 else device_id
        detail_row = QHBoxLayout()
        id_label = QLabel(f"ID: {short_id}")
        id_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        detail_row.addWidget(id_label)

        state_label = QLabel(state)
        state_label.setStyleSheet(f"color: {_STATE_COLORS.get(state, COLOR_TEXT_MUTED)}; font-weight: 600;")
        detail_row.addWidget(state_label)
        detail_row.addStretch()

        if viewer_is_authorized and not is_self and state == "PENDING":
            authorize_button = QPushButton("Authorize")
            authorize_button.setCursor(Qt.PointingHandCursor)
            authorize_button.clicked.connect(
                lambda checked=False, d=device: self._handle_authorize(d)
            )
            detail_row.addWidget(authorize_button)

        if viewer_is_authorized and not is_self and state == "AUTHORIZED":
            if self.session.get_peer_verification_state(device_id) == PEER_STATE_VERIFIED:
                send_keys_button = QPushButton("Send keys")
                send_keys_button.setToolTip(
                    "Send this device's conversation keys to that verified device so it can read your history."
                )
                send_keys_button.setCursor(Qt.PointingHandCursor)
                send_keys_button.clicked.connect(
                    lambda checked=False, d=device: self._handle_send_keys(d)
                )
                detail_row.addWidget(send_keys_button)
            else:
                verify_button = QPushButton("Verify")
                verify_button.setToolTip(
                    "Compare this device's safety number with the one it shows, to trust it with your keys."
                )
                verify_button.setCursor(Qt.PointingHandCursor)
                verify_button.clicked.connect(
                    lambda checked=False, d=device: self._handle_verify(d)
                )
                detail_row.addWidget(verify_button)

        if viewer_is_authorized and state == "AUTHORIZED":
            revoke_button = QPushButton("Revoke")
            revoke_button.setObjectName("DangerButton")
            revoke_button.setCursor(Qt.PointingHandCursor)
            revoke_button.clicked.connect(
                lambda checked=False, d=device: self._handle_revoke(d)
            )
            detail_row.addWidget(revoke_button)

        row_layout.addLayout(detail_row)

        item = QListWidgetItem()
        item.setSizeHint(row.sizeHint())
        self._device_list.addItem(item)
        self._device_list.setItemWidget(item, row)

    # ==========================================================
    # Actions
    # ==========================================================

    def _confirm_safety_number(self, title, device, fingerprint, consequence):
        """Ask the person to compare ``fingerprint`` -- computed here from the device's keys, not
        taken from the server -- with the number the OTHER device shows for itself. "No" is the
        default, so pressing Enter never trusts a device."""

        name = device.get("device_name") or device.get("device_id")

        answer = QMessageBox.question(
            self,
            title,
            f"Check that \"{name}\" shows exactly this as its own safety number:\n\n"
            f"{fingerprint}\n\n"
            "Where to find it on that device: Website - open a contact's safety details and choose "
            "\"Show my safety number\"; Desktop - open this Devices window (\"This device's safety number\") "
            "or Verify identity on a contact (\"Your safety number\").\n\n"
            f"If it differs in any way, choose No. {consequence}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        return answer == QMessageBox.Yes

    def _handle_authorize(self, device):
        device_id = device.get("device_id")

        try:
            fingerprint = self.session.observe_own_device(device)
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(str(error))
            return

        if not self._confirm_safety_number(
            "Authorize device", device, fingerprint,
            "Authorizing lets this device sign in as you and request your conversation keys.",
        ):
            return

        try:
            self.session.confirm_device_peer_verification(device_id, fingerprint)
            result = self.session.authorize_device(device_id, fingerprint)
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(str(error))
            return

        if result.get("success"):
            self._status_label.setStyleSheet(f"color: {COLOR_ONLINE};")
            self._status_label.setText(f"Authorized {device.get('device_name') or device.get('device_id')}.")
            self._refresh()
        else:
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(result.get("error") or "Could not authorize device.")

    def _handle_verify(self, device):
        device_id = device.get("device_id")
        name = device.get("device_name") or device_id

        try:
            fingerprint = self.session.observe_own_device(device)
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(str(error))
            return

        if not self._confirm_safety_number(
            "Verify device", device, fingerprint,
            "A verified device can be sent your conversation keys.",
        ):
            return

        try:
            self.session.confirm_device_peer_verification(device_id, fingerprint)
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(str(error))
            return

        self._status_label.setStyleSheet(f"color: {COLOR_ONLINE};")
        self._status_label.setText(f"Verified {name}.")
        self._refresh()

    def _handle_send_keys(self, device):
        device_id = device.get("device_id")
        name = device.get("device_name") or device_id

        try:
            self.session.observe_own_device(device)
            sent, failures = self.session.sync_all_conversation_keys_to_device(device_id)
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(str(error))
            return

        if failures:
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(
                f"Sent {sent} key(s) to {name}; {len(failures)} could not be sent "
                f"({failures[0][2] or 'rejected'}). Is {name} online and bound?"
            )
        else:
            self._status_label.setStyleSheet(f"color: {COLOR_ONLINE};")
            self._status_label.setText(f"Sent {sent} conversation key(s) to {name}.")

    def _handle_revoke(self, device):
        try:
            result = self.session.revoke_device(device.get("device_id"))
        except Exception as error:  # noqa: BLE001
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(str(error))
            return

        if result.get("success"):
            self._status_label.setStyleSheet(f"color: {COLOR_ONLINE};")
            self._status_label.setText(f"Revoked {device.get('device_name') or device.get('device_id')}.")
            self._refresh()
        else:
            self._status_label.setStyleSheet(f"color: {COLOR_DANGER};")
            self._status_label.setText(result.get("error") or "Could not revoke device.")
