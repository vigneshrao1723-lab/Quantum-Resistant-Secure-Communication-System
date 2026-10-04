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
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.styles import COLOR_CLASSICAL, COLOR_DANGER, COLOR_ONLINE, COLOR_TEXT_MUTED

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

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Devices enrolled on this account"))
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

        if viewer_is_authorized and state == "AUTHORIZED":
            revoke_button = QPushButton("Revoke")
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

    def _handle_authorize(self, device):
        try:
            result = self.session.authorize_device(device.get("device_id"), device.get("fingerprint"))
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
