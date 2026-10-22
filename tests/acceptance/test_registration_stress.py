"""Repeated registrations through the real Website form (diagnoses intermittent loss)."""

import os

from tests.acceptance.conftest import new_identity
from tests.acceptance.web_driver import WebUser

REPEATS = int(os.environ.get("QRSCS_ACCEPT_STRESS", "40"))


def test_repeated_web_registrations_all_succeed(stack, browser):
    failures = []
    for i in range(REPEATS):
        ident = new_identity(f"reg{i:02d}")
        user = WebUser(browser, stack, ident["username"], ident["phone"], ident["password"])
        try:
            user.register()
        except AssertionError as error:
            failures.append(f"#{i}: {error}")
        finally:
            user.close()

    assert not failures, "\n".join(failures)
