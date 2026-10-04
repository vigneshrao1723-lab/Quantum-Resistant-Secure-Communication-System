"""
Models package.

Importing this package (or any of its submodules, since Python always
imports the parent package first) registers every mapped class on
``Base.metadata`` and resolves the string-based relationship references
between them (e.g. User.sessions -> "Session"). Without this, importing
a single model module in isolation can fail with an SQLAlchemy
InvalidRequestError because the referenced class hasn't been registered
yet.
"""

from database.models.base import Base
from database.models.blocked_user import BlockedUser
from database.models.conversation import Conversation
from database.models.conversation_member import ConversationMember
from database.models.device import Device
from database.models.inbox_notification import InboxNotification
from database.models.message import Message
from database.models.message_hidden_for_user import MessageHiddenForUser
from database.models.message_reaction import MessageReaction
from database.models.message_recipient import MessageRecipient
from database.models.session import Session
from database.models.user import User

__all__ = [
    "Base",
    "BlockedUser",
    "Conversation",
    "ConversationMember",
    "Device",
    "InboxNotification",
    "Message",
    "MessageHiddenForUser",
    "MessageReaction",
    "MessageRecipient",
    "Session",
    "User",
]
