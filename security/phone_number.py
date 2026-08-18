"""
Phone-number normalisation and validation.

The single place a phone number is turned into its canonical form
(BUG 7 -- phone-based user discovery). Registration stores what this
module returns, and lookup canonicalises the search term the same way,
so the two can only ever agree. Doing it in one module is what makes
the UNIQUE constraint on users.phone_number mean what it should: the
same real-world number written three different ways collides, instead
of registering three times.

    "+91 98765 43210"  ->  "+919876543210"
    "+91-98765-43210"  ->  "+919876543210"
    "+919876543210"    ->  "+919876543210"

Deliberately NOT a full E.164 implementation. There is no country
database, no carrier lookup, and no check that the number exists or is
reachable -- that would need a library and, to mean anything, an SMS
round trip. This module answers one narrower question: is this string
a plausible phone number, and what is its canonical form? Ownership is
NOT verified anywhere in this project (no OTP -- explicitly out of
scope), so a phone number here identifies an account, never a verified
person.

Client-side code may import this module: it depends only on the
standard library, and pulls in nothing server-side (see
tests/test_client_import_boundary.py for why that matters).
"""

# E.164 allows at most 15 digits. Seven is the shortest number in real
# national use, so anything shorter is a typo rather than a number.
MIN_DIGITS = 7
MAX_DIGITS = 15

# Everything a person might reasonably type as separators.
_SEPARATORS = " -()./ \t"


class InvalidPhoneNumberError(ValueError):
    """Raised for a string that cannot be a phone number.

    A ValueError subclass so callers that already catch ValueError for
    bad input -- the convention throughout this codebase -- keep
    working unchanged.
    """


def normalize_phone_number(raw):
    """
    Return the canonical form of ``raw``.

    Accepts the separators people actually type (spaces, dashes,
    parentheses, dots, non-breaking spaces) and an optional leading
    "+", which is preserved because it is the difference between an
    international and a national number -- dropping it would let
    "+919876543210" and "919876543210" collide as one account.

    Raises InvalidPhoneNumberError for anything that is not a
    plausible number: empty, non-string, letters, an interior "+", or
    a digit count outside MIN_DIGITS..MAX_DIGITS.
    """

    if not isinstance(raw, str):
        raise InvalidPhoneNumberError(
            f"Phone number must be a string, not {type(raw).__name__}."
        )

    candidate = raw.strip()

    if not candidate:
        raise InvalidPhoneNumberError("Phone number is required.")

    has_plus = candidate.startswith("+")

    if has_plus:
        candidate = candidate[1:]

    for separator in _SEPARATORS:
        candidate = candidate.replace(separator, "")

    if not candidate:
        raise InvalidPhoneNumberError("Phone number is required.")

    if not candidate.isdigit():
        # Catches letters, a second "+", and any other stray symbol.
        raise InvalidPhoneNumberError(
            "Phone number may contain only digits, an optional leading '+', "
            "and separators."
        )

    if len(candidate) < MIN_DIGITS:
        raise InvalidPhoneNumberError(
            f"Phone number must have at least {MIN_DIGITS} digits."
        )

    if len(candidate) > MAX_DIGITS:
        raise InvalidPhoneNumberError(
            f"Phone number must have at most {MAX_DIGITS} digits."
        )

    return ("+" if has_plus else "") + candidate


def is_valid_phone_number(raw):
    """True if ``raw`` normalises successfully. For callers that want a
    predicate rather than an exception (the GUI's inline validation)."""

    try:
        normalize_phone_number(raw)
    except InvalidPhoneNumberError:
        return False

    return True
