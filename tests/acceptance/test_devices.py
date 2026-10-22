"""Linking a second device, authorizing it, and revoking it, through the Website's Settings screen.

Two browser contexts log in to the SAME account, so the second is a genuinely separate device (its
own identity keys and storage). The Desktop's own Devices dialog is exercised by
tests/test_device_management.py and the device_security batch; its rows are list items that
assistive technology cannot reach, so it cannot be driven through UI Automation (recorded as a
limitation in the parity matrix).
"""

import re

from tests.acceptance.conftest import new_identity
from tests.acceptance.web_driver import WebUser, wait_until


def _device_id(user):
    return user.page.evaluate("window.__session.deviceId")


def test_second_device_is_authorized_then_revoked_from_the_first(browser, stack):
    ident = new_identity("dev")
    first = WebUser(browser, stack, ident["username"], ident["phone"], ident["password"])
    second = WebUser(browser, stack, ident["username"], ident["phone"], ident["password"])
    try:
        first.register()
        first.login()
        second.open()
        second.login()

        # The first device enrolls and, being first on the account, is authorized at once.
        first.page.click("#settingsToggleBtn")
        first.page.click("#enrollDeviceBtn")
        wait_until(lambda: "(AUTHORIZED)" in first.page.inner_text("#myDeviceId"), 20,
                   what="the first device to be enrolled and authorized")
        first.page.click("#bindDeviceBtn")
        try:
            wait_until(lambda: f"Bound this connection to device {_device_id(first)}" in first.page.inner_text("#log"),
                       20, what="the first device to bind")
        except AssertionError as error:
            raise AssertionError(f"{error}; log tail: {first.page.inner_text('#log')[-300:]!r}") from None

        # The second device enrolls and is PENDING.
        second.page.click("#settingsToggleBtn")
        second.page.click("#enrollDeviceBtn")
        wait_until(lambda: "(PENDING)" in second.page.inner_text("#myDeviceId"), 20, what="PENDING on the second device")
        second_id = _device_id(second)
        assert second_id and second_id != _device_id(first)

        # The first device sees it, compares its fingerprint, and authorizes it.
        first.page.click("#listDevicesBtn")
        wait_until(lambda: second_id in first.page.inner_text("#deviceList"), 20, what="the second device in the list")
        first.page.fill("#targetDeviceId", second_id)
        first.page.click("#observeDeviceBtn")
        wait_until(lambda: second_id in first.page.inner_text("#deviceFingerprintDisplay"), 20,
                   what="the second device's fingerprint")
        first.page.click("#authorizeDeviceBtn")
        wait_until(lambda: f"Authorized device {second_id}" in first.page.inner_text("#log"), 20, what="authorization")

        second.page.click("#bindDeviceBtn")
        wait_until(lambda: f"Bound this connection to device {second_id}" in second.page.inner_text("#log"), 20,
                   what="the authorized device to bind")

        # Revoked: the first device revokes it and it can no longer bind.
        first.page.click("#revokeDeviceBtn")
        wait_until(lambda: f"Revoked device {second_id}" in first.page.inner_text("#log"), 20, what="revocation")
        second.page.click("#bindDeviceBtn")
        wait_until(lambda: re.search(r"(revoked|not authorized|could not bind|failed)", second.page.inner_text("#log"),
                                     re.I) is not None, 20, what="the revoked device to be refused")
        assert not first.page_errors and not second.page_errors
    finally:
        first.close()
        second.close()
