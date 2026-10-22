"""Direct messaging between every combination of clients, all through the real UIs."""

import pytest

from tests.acceptance.parties import converse, verify_pair

COMBINATIONS = [("web", "web"), ("web", "desktop"), ("desktop", "web"), ("desktop", "desktop")]


@pytest.mark.parametrize("kind_a,kind_b", COMBINATIONS, ids=lambda k: k)
def test_two_users_verify_each_other_and_exchange_messages(party, kind_a, kind_b):
    a, b = party(kind_a, "pa"), party(kind_b, "pb")

    verify_pair(a, b)
    converse(a, b, f"{kind_a}-{kind_b}")

    assert not a.errors() and not b.errors(), (a.errors(), b.errors())
