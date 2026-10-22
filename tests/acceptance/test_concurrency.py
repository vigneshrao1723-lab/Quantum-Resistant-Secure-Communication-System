"""Many conversations at once among the standing population: nothing lost, duplicated or misrouted."""

import uuid

from tests.acceptance.parties import verify_pair
from tests.acceptance.web_driver import wait_until

MESSAGES_PER_DIRECTION = 4


def _pairs(population):
    """Disjoint pairs: a person takes part in exactly one conversation (a browser shows only one at a time)."""
    web = [p for p in population if p.kind == "web"]
    desktop = [p for p in population if p.kind == "desktop"]
    mixed = [(web[len(web) - 1 - i], desktop[i]) for i in range(min(len(desktop), len(web)))]   # web <-> desktop
    remaining = web[: len(web) - len(mixed)]
    pairs = [(remaining[i], remaining[i + 1]) for i in range(0, len(remaining) - 1, 2)]          # web <-> web
    pairs += mixed
    used = [p.username for pair in pairs for p in pair]
    assert len(used) == len(set(used)), "a participant appears in two pairs"
    return pairs


def test_simultaneous_conversations_deliver_every_message_exactly_once_to_the_right_person(population):
    pairs = _pairs(population)
    assert len(pairs) >= 4, "the population is too small for this scenario"
    run = uuid.uuid4().hex[:6]

    for a, b in pairs:
        verify_pair(a, b)
        a.start_secure_session()
        b.start_secure_session()

    # Every pair sends a burst in both directions before anyone waits for anything.
    expected = {}  # participant -> messages it must end up holding
    sent_by = {}   # message -> who sent it
    for index, (a, b) in enumerate(pairs):
        for n in range(MESSAGES_PER_DIRECTION):
            from_a = f"c{index}-{run}-a{n}"
            from_b = f"c{index}-{run}-b{n}"
            a.send(from_a)
            b.send(from_b)
            sent_by.update({from_a: a, from_b: b})
            expected.setdefault(b.username, []).append(from_a)
            expected.setdefault(a.username, []).append(from_b)

    # Each sender's own screen must show what it sent; otherwise the send itself failed.
    for text, sender in sent_by.items():
        sender.wait_for_text(text, timeout=30)

    for a, b in pairs:
        for person in (a, b):
            for text in expected[person.username]:
                try:
                    person.wait_for_text(text, timeout=60)
                except Exception as error:
                    sender = sent_by[text]
                    raise AssertionError(
                        f"{text!r} sent by {sender.username} ({sender.kind}) never reached {person.username} "
                        f"({person.kind}): {error}"
                    ) from None

    # Exactly once, and only conversation-mates' traffic: no message from another pair is present.
    for index, (a, b) in enumerate(pairs):
        for person in (a, b):
            seen = person.visible_text()
            for text in expected[person.username]:
                assert seen.count(text) == 1, f"{text!r} appears {seen.count(text)} times for {person.username}"
            for other_index in range(len(pairs)):
                if other_index != index:
                    assert f"c{other_index}-{run}-" not in seen, f"{person.username} saw another pair's message"

    assert all(not p.errors() for pair in pairs for p in pair)
