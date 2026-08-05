"""
Tests for security/password_handler.py.

No database required -- PasswordHandler is pure Argon2 hashing/validation
logic.

Run with:
    pytest tests/test_password_handler.py -v
"""

import pytest

from security.password_handler import PasswordHandler

VALID_PASSWORD = "Str0ng!Passw0rd"


@pytest.fixture()
def handler():
    return PasswordHandler()


def test_hash_and_verify_round_trip(handler):
    hashed = handler.hash_password(VALID_PASSWORD)
    assert hashed != VALID_PASSWORD
    assert handler.verify_password(hashed, VALID_PASSWORD) is True


def test_verify_rejects_wrong_password(handler):
    hashed = handler.hash_password(VALID_PASSWORD)
    assert handler.verify_password(hashed, "SomethingElse!123") is False


def test_verify_rejects_malformed_hash(handler):
    assert handler.verify_password("not-a-real-hash", VALID_PASSWORD) is False


def test_hash_is_salted_and_nondeterministic(handler):
    first = handler.hash_password(VALID_PASSWORD)
    second = handler.hash_password(VALID_PASSWORD)
    assert first != second
    assert handler.verify_password(first, VALID_PASSWORD) is True
    assert handler.verify_password(second, VALID_PASSWORD) is True


@pytest.mark.parametrize(
    "password,expected_violation_substring",
    [
        ("short1!A", "at least 12 characters"),
        ("alllowercase123!", "uppercase"),
        ("ALLUPPERCASE123!", "lowercase"),
        ("NoDigitsHere!!", "digit"),
        ("NoSpecialChars123", "special character"),
    ],
)
def test_policy_violations_detected(handler, password, expected_violation_substring):
    violations = handler.get_password_policy_violations(password)
    assert any(expected_violation_substring in v for v in violations)
    assert handler.validate_password_policy(password) is False


def test_policy_accepts_compliant_password(handler):
    assert handler.get_password_policy_violations(VALID_PASSWORD) == []
    assert handler.validate_password_policy(VALID_PASSWORD) is True


def test_needs_rehash_false_for_current_params(handler):
    hashed = handler.hash_password(VALID_PASSWORD)
    assert handler.needs_rehash(hashed) is False


def test_needs_rehash_false_for_malformed_hash(handler):
    # Should degrade gracefully rather than raise on garbage input.
    assert handler.needs_rehash("not-a-real-hash") is False
