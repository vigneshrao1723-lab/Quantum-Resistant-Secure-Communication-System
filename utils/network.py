"""
Network Utilities

Provides reliable send/receive functions using
length-prefixed TCP messages.
"""

import json
import struct
import threading
import weakref

# One Lock per socket, synchronizing every send_message() call against
# that socket -- sendall() is not atomic across threads (it can issue
# several underlying send() syscalls, and Python releases the GIL
# during blocking socket I/O), so two threads writing to the SAME
# socket at once can interleave their bytes on the wire, corrupting
# both messages (and, over TLS, the record framing itself, surfacing
# as a decrypt/MAC failure on the receiving end). The server
# legitimately has multiple threads that can each end up targeting the
# same client socket (broadcast/relay/fan-out from a different
# connection's own thread), so this must be per-socket, not a single
# global lock -- writes to different sockets still proceed fully in
# parallel. A WeakKeyDictionary so a closed/garbage-collected socket's
# entry is dropped automatically instead of growing unbounded across a
# long-running server's connect/disconnect churn.
_write_locks = weakref.WeakKeyDictionary()
_write_locks_guard = threading.Lock()


def _get_write_lock(sock):
    """Return the one Lock synchronizing every write to ``sock``,
    creating it on first use."""

    with _write_locks_guard:

        lock = _write_locks.get(sock)

        if lock is None:
            lock = threading.Lock()
            _write_locks[sock] = lock

        return lock


def send_message(sock, message):
    """
    Send a JSON packet with a 4-byte length prefix. Serialized per
    socket -- see _get_write_lock()'s docstring.
    """

    # Convert dictionary to JSON string
    if isinstance(message, dict):
        message = json.dumps(message)

    data = message.encode("utf-8")

    length = struct.pack("!I", len(data))

    with _get_write_lock(sock):
        sock.sendall(length + data)


def receive_message(sock):
    """
    Receive a complete JSON packet.

    Returns:
        dict, string or None
    """

    header = recvall(sock, 4)

    if not header:
        return None

    length = struct.unpack("!I", header)[0]

    data = recvall(sock, length)

    if not data:
        return None

    message = data.decode("utf-8")

    # Try to convert JSON back into a dictionary
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        # Username and other plain strings remain strings
        return message


def recvall(sock, n):
    """
    Receive exactly n bytes from the socket.
    """

    data = b""

    while len(data) < n:

        packet = sock.recv(n - len(data))

        if not packet:
            return None

        data += packet

    return data