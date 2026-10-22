"""Registration and login of the whole synthetic population through the real UIs."""

from tests.acceptance.conftest import LEDGER, POPULATION_DESKTOP, POPULATION_WEB


def test_every_account_registers_and_logs_in_through_the_ui(population):
    failures = [e for e in LEDGER if not (e["registered"] and e["logged_in"])]

    assert not failures, failures
    assert len(population) == POPULATION_WEB + POPULATION_DESKTOP
    assert len({p.username for p in population}) == len(population)  # distinct identities


def test_every_account_has_its_own_identity_keys(population):
    # A Desktop account reads its own number in a contact's verification window, so each one first
    # opens a chat with a Website account (the first that is not itself).
    anchor = next(p for p in population if p.kind == "web")
    for party in population:
        if party.kind == "desktop":
            party.open_chat_with(anchor)

    numbers = [p.own_fingerprint() for p in population]

    assert all(len(n) == 64 for n in numbers)
    assert len(set(numbers)) == len(numbers), "two accounts share an identity"
