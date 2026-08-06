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
from database.models.message import Message
from database.models.session import Session
from database.models.user import User

__all__ = ["Base", "Message", "Session", "User"]
