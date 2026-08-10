"""
Payload domain model.

The first stage of the universal pipeline:

    Payload -> Serialization -> Encryption -> Packet -> Network

Framework-free (no Qt, no SQLAlchemy, no network, no crypto
dependency), mirroring domain/conversation_summary.py's style.
Represents content before it has been turned into bytes --
``content`` is a str for "text" today; a future binary payload type
(file, image, voice, video) would use raw bytes instead. Only
domain/payload_serializer.py interprets ``content`` further.
"""

from dataclasses import dataclass, field
from typing import Any

from domain.payload_type import PayloadType


@dataclass
class Payload:
    """Native, pre-serialization content for one payload_type."""

    payload_type: PayloadType
    content: str | bytes
    content_metadata: dict[str, Any] = field(default_factory=dict)
