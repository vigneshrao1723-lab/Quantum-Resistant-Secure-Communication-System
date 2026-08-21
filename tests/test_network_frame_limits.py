"""
D8 / L-2 + L-3 -- frame-size limit and socket timeouts.

utils/network.py::receive_message() is the ONLY socket read path in
the system (client receiver, client request/response, server
authentication and server dispatch all call it), so these two
protections live in one place and this file tests that place.

Before L-2 the 4-byte "!I" length prefix was passed straight to
recvall(), admitting a declared length of up to 4,294,967,295 bytes
from an unauthenticated peer.

Before L-3 nothing in the project ever called settimeout(), so a peer
could send one byte of a header and hold a server thread forever.
"""

import socket
import struct
import threading

import pytest

from config import MAX_ATTACHMENT_SIZE_BYTES, MAX_FRAME_BYTES
from utils import network
from utils.network import (
    FrameStalledError,
    FrameTooLargeError,
    receive_message,
    recvall,
    send_message,
)


@pytest.fixture()
def pair():
    """A connected socket pair: (server_side, client_side)."""

    left, right = socket.socketpair()

    yield left, right

    for sock in (left, right):
        try:
            sock.close()
        except OSError:
            pass


def _frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


# ----------------------------------------------------------------------
# L-2 -- the cap itself
# ----------------------------------------------------------------------


def test_limit_is_derived_from_the_attachment_limit_not_guessed():
    """A "round" 32 MiB cap would reject legitimate attachments: the
    payload pipeline base64-encodes twice (once in payload_cipher
    before encrypting, once in aes after), so a frame is 16/9 the file
    size. Measured: a 25 MiB attachment produces a 46,604,005-byte
    frame."""

    measured_max_real_frame = 46_604_005

    assert MAX_FRAME_BYTES >= measured_max_real_frame, (
        f"MAX_FRAME_BYTES ({MAX_FRAME_BYTES:,}) would reject a legitimate "
        f"maximum-size attachment ({measured_max_real_frame:,} bytes)"
    )
    assert MAX_FRAME_BYTES >= MAX_ATTACHMENT_SIZE_BYTES * 16 // 9


def test_oversized_declared_length_is_rejected(pair):
    """The core L-2 regression. Fails against the old code, which
    accepted the declaration and began accumulating."""

    server_side, client_side = pair

    client_side.sendall(struct.pack("!I", MAX_FRAME_BYTES + 1))

    with pytest.raises(FrameTooLargeError):
        receive_message(server_side)


def test_maximum_possible_declared_length_is_rejected(pair):
    """0xFFFFFFFF -- what "!I" actually admits, and what the old code
    would have tried to read."""

    server_side, client_side = pair

    client_side.sendall(struct.pack("!I", 0xFFFFFFFF))

    with pytest.raises(FrameTooLargeError):
        receive_message(server_side)


def test_oversized_frame_is_rejected_before_the_payload_is_read(pair):
    """Rejecting late would be nearly worthless: the memory would
    already have been spent. Only the 4 header bytes may be consumed.

    Proven by sending the header plus a marker, then showing the
    marker is still sitting unread in the buffer afterwards.
    """

    server_side, client_side = pair

    marker = b"UNREAD-MARKER"
    client_side.sendall(struct.pack("!I", MAX_FRAME_BYTES + 1) + marker)

    with pytest.raises(FrameTooLargeError):
        receive_message(server_side)

    server_side.settimeout(2)

    assert server_side.recv(len(marker)) == marker, (
        "the payload was consumed before the frame was rejected"
    )


def test_frame_at_exactly_the_limit_is_accepted(pair):
    """Boundary: the cap is inclusive, so a frame of exactly
    MAX_FRAME_BYTES must still work. Uses a shrunken limit so the test
    does not have to move 45 MB."""

    server_side, client_side = pair

    payload = b'"' + b"x" * 62 + b'"'

    original = network.MAX_FRAME_BYTES
    try:
        network.MAX_FRAME_BYTES = len(payload)
        client_side.sendall(_frame(payload))

        assert receive_message(server_side) == payload[1:-1].decode()
    finally:
        network.MAX_FRAME_BYTES = original


def test_one_byte_over_a_shrunken_limit_is_rejected(pair):
    server_side, client_side = pair

    payload = b'"' + b"x" * 62 + b'"'

    original = network.MAX_FRAME_BYTES
    try:
        network.MAX_FRAME_BYTES = len(payload) - 1
        client_side.sendall(_frame(payload))

        with pytest.raises(FrameTooLargeError):
            receive_message(server_side)
    finally:
        network.MAX_FRAME_BYTES = original


def test_sending_an_oversized_frame_is_refused(pair):
    """Guarded outbound too, so this process never emits a frame the
    peer is obliged to drop."""

    server_side, _client_side = pair

    original = network.MAX_FRAME_BYTES
    try:
        network.MAX_FRAME_BYTES = 16

        with pytest.raises(FrameTooLargeError):
            send_message(server_side, {"padding": "x" * 500})
    finally:
        network.MAX_FRAME_BYTES = original


def test_frame_errors_are_value_errors():
    """Existing callers already treat malformed input as ValueError."""

    assert issubclass(FrameTooLargeError, ValueError)


# ----------------------------------------------------------------------
# L-2 -- malformed and fragmented frames
# ----------------------------------------------------------------------


def test_truncated_header_returns_none(pair):
    server_side, client_side = pair

    client_side.sendall(b"\x00\x00")
    client_side.close()

    assert receive_message(server_side) is None


def test_closed_connection_returns_none(pair):
    server_side, client_side = pair

    client_side.close()

    assert receive_message(server_side) is None


def test_truncated_body_returns_none(pair):
    """Header promises 100 bytes, peer sends 10 then hangs up."""

    server_side, client_side = pair

    client_side.sendall(struct.pack("!I", 100) + b"0123456789")
    client_side.close()

    assert receive_message(server_side) is None


def test_zero_length_frame_returns_none(pair):
    server_side, client_side = pair

    client_side.sendall(struct.pack("!I", 0))
    client_side.close()

    assert receive_message(server_side) is None


def test_non_json_body_is_returned_as_a_string(pair):
    """Pre-existing behaviour, preserved: plain strings stay strings."""

    server_side, client_side = pair

    client_side.sendall(_frame(b"not json at all"))

    assert receive_message(server_side) == "not json at all"


def test_fragmented_frame_is_reassembled(pair):
    """A frame delivered in many small writes must arrive intact --
    this is also the path recvall()'s chunk-list rewrite changed."""

    server_side, client_side = pair

    packet = {"type": "chat", "message": "y" * 5000}

    import json

    body = json.dumps(packet).encode("utf-8")
    wire = _frame(body)

    def dribble():
        for index in range(0, len(wire), 97):
            client_side.sendall(wire[index:index + 97])

    sender = threading.Thread(target=dribble)
    sender.start()

    received = receive_message(server_side)

    sender.join(timeout=10)

    assert received == packet


def test_two_frames_back_to_back_do_not_bleed_into_each_other(pair):
    server_side, client_side = pair

    client_side.sendall(_frame(b'{"n": 1}') + _frame(b'{"n": 2}'))

    assert receive_message(server_side) == {"n": 1}
    assert receive_message(server_side) == {"n": 2}


# ----------------------------------------------------------------------
# L-3 -- stall vs idle
# ----------------------------------------------------------------------


def test_partially_delivered_frame_times_out(pair):
    """The slowloris regression: a peer sends a header and part of a
    body, then stops. Before L-3 this blocked forever.

    The deadline is set on the SOCKET, which is how production does
    it -- recvall() reads whatever deadline the socket owner set and
    only decides what a timeout means."""

    server_side, client_side = pair

    server_side.settimeout(0.3)

    client_side.sendall(struct.pack("!I", 5000) + b"partial")

    with pytest.raises(FrameStalledError):
        receive_message(server_side)


def test_partial_header_times_out(pair):
    """One byte of the 4-byte header, then silence -- the cheapest
    version of the same attack."""

    server_side, client_side = pair

    server_side.settimeout(0.3)

    client_side.sendall(b"\x00")

    with pytest.raises(FrameStalledError):
        receive_message(server_side)


def test_an_idle_connection_is_never_disconnected(pair):
    """The other half of L-3, and the one that protects real users: a
    client sitting in a quiet conversation has sent NOTHING, and must
    not be treated as stalled. Without this distinction the timeout
    would disconnect every idle user."""

    server_side, client_side = pair

    server_side.settimeout(0.2)
    result = {}

    def reader():
        try:
            result["value"] = receive_message(server_side, allow_idle=True)
        except BaseException as error:  # noqa: BLE001
            result["error"] = error

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    # Stay silent for several stall windows, then finally speak.
    thread.join(timeout=1.2)

    assert thread.is_alive(), (
        f"an idle connection was dropped: {result.get('error')!r}"
    )

    client_side.sendall(_frame(b'{"late": true}'))
    thread.join(timeout=5)

    assert "error" not in result, result.get("error")
    assert result["value"] == {"late": True}


def test_a_slow_but_progressing_sender_is_not_disconnected(pair):
    """Legitimate slow uplinks must survive. The timeout bounds a lack
    of PROGRESS, not total transfer time."""

    server_side, client_side = pair

    server_side.settimeout(0.5)

    body = b'{"slow": "' + b"z" * 400 + b'"}'
    wire = _frame(body)

    def trickle():
        import time

        for index in range(0, len(wire), 40):
            client_side.sendall(wire[index:index + 40])
            time.sleep(0.05)

    sender = threading.Thread(target=trickle)
    sender.start()

    received = receive_message(server_side)

    sender.join(timeout=10)

    assert received["slow"].startswith("z")


def test_allow_idle_false_refuses_a_silent_peer(pair):
    """The server reads with allow_idle=False for the whole
    pre-authentication phase. There, a peer that sends nothing at all
    IS the attack, so idle tolerance must not apply -- otherwise the
    handshake deadline would be silently defeated."""

    server_side, _client_side = pair

    server_side.settimeout(0.3)

    with pytest.raises(FrameStalledError):
        receive_message(server_side, allow_idle=False)


def test_recvall_does_not_modify_the_socket_timeout(pair):
    """Ownership of the deadline belongs to the code that owns the
    socket's lifecycle. An earlier version set and restored the
    timeout on every read, which toggled a live SSLSocket between
    blocking and non-blocking mode twice per packet for the whole life
    of the connection."""

    server_side, client_side = pair

    server_side.settimeout(7.5)

    client_side.sendall(b"abcd")
    recvall(server_side, 4, idle_ok=True)

    assert server_side.gettimeout() == 7.5


def test_a_socket_with_no_timeout_behaves_as_before(pair):
    """Unchanged legacy behaviour: with no deadline set, a read simply
    blocks until data or EOF. The integration harnesses rely on it."""

    server_side, client_side = pair

    assert server_side.gettimeout() is None

    client_side.sendall(_frame(b'{"ok": 1}'))

    assert receive_message(server_side) == {"ok": 1}
    assert server_side.gettimeout() is None


def test_the_default_does_not_swallow_a_callers_timeout(pair):
    """Regression, caught by tests/test_offline_messaging.py.

    Idle tolerance was briefly the DEFAULT for receive_message(). That
    hung every caller that sets a short socket timeout on purpose so it
    can poll and retry -- the integration harness's own _recv_until()
    helper does exactly that, and it looped forever instead of raising.

    Idle tolerance must therefore be opt-IN, used only by the two
    long-lived read loops (the server's dispatch loop and the client's
    receiver thread).
    """

    server_side, _client_side = pair

    server_side.settimeout(0.2)

    # Nothing is ever sent. The caller's deadline must surface rather
    # than being absorbed into an endless retry.
    with pytest.raises((FrameStalledError, socket.timeout, OSError)):
        receive_message(server_side)


def test_idle_tolerance_is_opt_in():
    """Structural companion to the test above."""

    import inspect

    signature = inspect.signature(receive_message)

    assert signature.parameters["allow_idle"].default is False, (
        "allow_idle must default to False -- see the regression above"
    )
