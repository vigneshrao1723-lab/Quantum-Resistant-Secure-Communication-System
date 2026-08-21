"""
Network Utilities

Provides reliable send/receive functions using
length-prefixed TCP messages.
"""

import json
import socket
import struct
import threading
import weakref

from config import MAX_FRAME_BYTES


class FrameStalledError(OSError):
    """
    A frame started arriving and then stopped making progress for
    longer than config.SOCKET_STALL_TIMEOUT_SECONDS (D8 / L-3).

    Deliberately NOT raised for an idle connection: a client waiting
    quietly for the next message has sent nothing at all, which is
    normal. This is only ever a PARTIALLY delivered frame -- see
    recvall(). An OSError subclass because that is what callers
    already expect from a socket that has gone bad.
    """


class FrameTooLargeError(ValueError):
    """
    A peer declared, or this process tried to send, a frame larger
    than config.MAX_FRAME_BYTES (D8 / L-2).

    Raised BEFORE any payload byte is read or allocated, so an
    oversized declaration costs the receiver the 4 header bytes and
    nothing else. A ValueError subclass so existing callers that
    already treat malformed input as ValueError keep working.
    """

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

    # Guarded on the way out as well as the way in. Emitting a frame
    # the peer is required to reject wastes the whole transfer and
    # then looks like an unexplained disconnect; failing here names
    # the real cause at the point it can still be reported.
    if len(data) > MAX_FRAME_BYTES:
        raise FrameTooLargeError(
            f"Refusing to send a {len(data):,}-byte frame; the maximum is "
            f"{MAX_FRAME_BYTES:,} bytes."
        )

    length = struct.pack("!I", len(data))

    with _get_write_lock(sock):
        sock.sendall(length + data)


def receive_message(sock, allow_idle=False):
    """
    Receive a complete JSON packet.

    ``allow_idle`` says whether having received NOTHING yet is normal
    on this read (D8 / L-3). Pass True only from a long-lived read
    loop that is supposed to sit waiting for the next message
    indefinitely -- the server's dispatch loop and the client's
    receiver thread. There, a socket deadline firing on a quiet
    connection is absorbed and the read resumes, so an idle user is
    never disconnected.

    It defaults to FALSE so that every other caller keeps exactly the
    behaviour it had before this parameter existed: whatever deadline
    the socket carries is honoured, and a timeout propagates. Several
    callers -- including the integration harness's own poll helpers --
    set a short timeout precisely so they can retry, and silently
    swallowing it would hang them forever.

    Returns:
        dict, string or None
    """

    header = recvall(sock, 4, idle_ok=allow_idle)

    if not header:
        return None

    length = struct.unpack("!I", header)[0]

    # D8 / L-2 -- the whole point of the cap. "!I" admits lengths up
    # to 4,294,967,295, and the previous code passed whatever it read
    # straight to recvall(), which would sit there accumulating for as
    # long as a hostile peer kept feeding it. Checked here, before
    # recvall() is entered, so nothing is allocated for a frame that
    # is never going to be accepted.
    if length > MAX_FRAME_BYTES:
        raise FrameTooLargeError(
            f"Peer declared a {length:,}-byte frame; the maximum is "
            f"{MAX_FRAME_BYTES:,} bytes."
        )

    # idle_ok is False here: the peer has already committed to a
    # frame of this length by sending the header, so a body that
    # stops arriving is a stalled frame, not an idle connection.
    data = recvall(sock, length, idle_ok=False)

    if not data:
        return None

    message = data.decode("utf-8")

    # Try to convert JSON back into a dictionary
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        # Username and other plain strings remain strings
        return message


def recvall(sock, n, idle_ok=False):
    """
    Receive exactly n bytes from the socket.

    Callers must bound ``n`` before calling -- receive_message()
    rejects anything over MAX_FRAME_BYTES first (D8 / L-2).

    ``idle_ok`` distinguishes the two kinds of waiting (D8 / L-3).
    With idle_ok=True, a timeout that fires while NOTHING has been
    received yet simply resumes waiting -- that is a connection
    sitting quietly between messages, which is normal and must never
    be disconnected. Once at least one byte has arrived, or whenever
    idle_ok is False, a timeout means a frame stopped part-way through
    and FrameStalledError is raised.

    This function deliberately does NOT call settimeout() itself. It
    reads whatever deadline the socket's owner has already set, and
    only decides what a timeout MEANS.

    An earlier version set the stall timeout on entry and restored the
    previous value in a finally, which read well but toggled a live
    SSLSocket between blocking and non-blocking mode twice per packet
    for the entire life of the connection. That is a poor thing to do
    to an active TLS session -- OpenSSL's retry semantics differ
    between the two modes -- and the server harness's leaked-handler-
    thread guard flagged exactly that shape. Ownership of the deadline
    now sits with the code that owns the socket's lifecycle
    (server/server.py and server/client_handler.py), which sets it
    once per phase.

    A socket with no timeout set behaves exactly as it did before any
    of this existed: recv() blocks until data or EOF.

    Chunks are collected in a list and joined once rather than
    concatenated with ``data += packet``. Repeated concatenation
    rebuilds the whole buffer on every iteration, which is quadratic
    in the frame size: for a legitimate 46 MB attachment frame
    arriving in small TCP segments that is a lot of pointless
    copying, and it was CPU an attacker could spend for free by
    dribbling bytes in one at a time.
    """

    chunks = []
    received = 0

    while received < n:

        try:
            packet = sock.recv(n - received)
        except socket.timeout as error:

            if idle_ok and received == 0:
                # Nothing has arrived at all -- an idle connection,
                # not a stalled frame. Keep waiting.
                continue

            raise FrameStalledError(
                f"Frame stalled after {received:,} of {n:,} bytes "
                f"({sock.gettimeout()}s without progress)."
            ) from error

        if not packet:
            return None

        chunks.append(packet)
        received += len(packet)

    return b"".join(chunks)