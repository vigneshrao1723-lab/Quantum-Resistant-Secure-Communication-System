"""
Message delivery status enum.

Per-recipient delivery state for group messages
(database/models/message_recipient.py), separated from message
content (database/models/message.py) so it can extend to read
receipts without a redesign.

A StrEnum, matching domain/payload_type.py's precedent: every state a
future phase needs (READ, FAILED) already exists as a member here,
unused until that phase writes it -- adding a *new* state later still
needs no schema migration, only a new member.
"""

from enum import StrEnum


class MessageDeliveryStatus(StrEnum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"
