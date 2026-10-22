"""The packaged Desktop executable talking to the Website, with every step done through the UI.

Alice uses the built ``QRSCS-Desktop.exe`` (registration, login, finding a user,
identity verification, messaging); Bob uses the Website in Chrome. Nothing is
inserted into the database directly.
"""

from tests.acceptance import desktop_driver as dd
from tests.acceptance.conftest import digits
from tests.acceptance.web_driver import safety_digits, wait_until


def test_exe_and_website_exchange_messages_end_to_end(stack, desktop_user, web_user, run_dir):
    alice = desktop_user("alice")
    bob = web_user("bob")

    # 1. Real registration and login on both clients.
    dd.register(alice, alice.username, alice.phone, alice.password)
    dd.login(alice, alice.phone, alice.password)
    bob.register()
    bob.login()
    assert alice.alive()

    # 2. Alice finds Bob by phone number and opens a chat; Bob opens the chat with Alice.
    dd.open_chat_by_phone(alice, bob.phone)
    bob.open_chat(alice.username)

    # 3. Out-of-band verification. Each client shows the OTHER person's safety number, so Alice's
    #    Verify Identity dialog must show Bob's own number (computed independently in Bob's browser).
    desktop_shows_bob = digits(dd.read_fingerprint_in_verify_dialog(alice))
    bobs_own = safety_digits("] " + bob.own_fingerprint())
    assert len(desktop_shows_bob) == 64, desktop_shows_bob
    assert desktop_shows_bob == bobs_own, "Desktop shows a different identity for Bob than Bob's own keys"
    assert len(safety_digits(bob.safety_number())) == 64  # Bob's page shows a full number for Alice
    dd.confirm_fingerprint_match(alice)
    bob.confirm_match()

    # 4. Session key, then messages in both directions.
    bob.establish_key()
    dd.send_message(alice, "hello from the packaged desktop app")
    bob.wait_for_message("hello from the packaged desktop app")
    bob.send("hello from the website")
    alice.wait_for(lambda: "hello from the website" in dd.conversation_text(alice), timeout=30,
                   what="Website message on the Desktop")

    assert not bob.page_errors and not bob.console_errors, (bob.page_errors, bob.console_errors)
    assert alice.alive()
