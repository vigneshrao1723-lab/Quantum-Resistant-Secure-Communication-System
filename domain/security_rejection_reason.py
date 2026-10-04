"""
Key-establishment security-rejection reason enum (Phase 13.7 --
Key-Establishment Rejection Observability & State Integrity).

Before this phase, ClientSession.handle_group_key_distribution() (Phase
13, KYBER/group-key) and ClientSession.handle_session_key() (Phase
13.6, RSA) already rejected forged/unverified/malformed key-
establishment packets correctly -- fail-closed, no crash -- but every
rejection was a bare ``return`` after a log line: nothing internally
distinguishable, and nothing any future caller (a test, or a Phase-14
GUI) could react to without parsing log text. This enum is the small,
explicit classification client/session.py's two receiver handlers now
return on rejection (``None`` on success -- see ClientSession.
security_rejection Signal and _report_security_rejection()).

A StrEnum, matching domain/payload_type.py's and domain/
message_delivery_status.py's precedent: members ARE str instances, so
one can compare/log/serialize a reason with no extra conversion step,
and a future reason is one new member, never a schema change.

Not every member below has a currently-distinguishable code path in
both handlers (see client/session.py's own docstrings for which
member each rejection point actually returns) -- this enum defines the
full vocabulary Part 3 of this phase specifies, wired up wherever the
current implementation can genuinely tell the cases apart without
inventing a new check purely to populate an unused label.
"""

from enum import StrEnum


class SecurityRejectionReason(StrEnum):
    UNKNOWN_SENDER = "unknown_sender"
    UNVERIFIED_SENDER = "unverified_sender"
    KEY_CHANGED = "key_changed"
    MISSING_SIGNATURE = "missing_signature"
    INVALID_SIGNATURE = "invalid_signature"
    MALFORMED_PACKET = "malformed_packet"
    WRONG_RECEIVER = "wrong_receiver"
    WRONG_CONVERSATION = "wrong_conversation"
    WRONG_ALGORITHM = "wrong_algorithm"
    INVALID_EPOCH = "invalid_epoch"
    DUPLICATE_OR_STALE_KEY = "duplicate_or_stale_key"
    DECRYPTION_FAILURE = "decryption_failure"
    OTHER_SECURITY_REJECTION = "other_security_rejection"
