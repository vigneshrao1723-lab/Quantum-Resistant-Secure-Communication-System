"""
Unit tests for D1 -- Request/Response Infrastructure.

Three layers, matching what D1 actually adds and how it's wired in:

  1. PendingRequestRegistry in complete isolation (no sockets, no
     ClientSession) -- the correlation primitive itself: register/
     resolve/wait, concurrent requests, timeout behavior, and
     resolving an id nobody is waiting for.

  2. ClientSession.send_request()/handle_packet() -- the real wiring,
     exercised over a genuine connected socket pair (socket.socketpair(),
     no TLS/server needed) so send_request()'s blocking behavior is
     tested against real socket I/O and a real background thread, not
     a mock standing in for one. handle_packet() is called directly
     from the test thread here, which proves the correlation logic
     itself is correct but not that the actual receiver thread's read
     loop survives it -- that's section 3.

  3. The real receiver thread (client/receiver.py::receive_messages(),
     started the same way ClientSession.start_receiver() starts it in
     production) reading real socket data and calling handle_packet()
     itself, not the test thread. This is the one integration-style
     test proving that a caller blocked in send_request() does not
     stall or kill the background dispatch loop -- the receiver thread
     resolves the correlated response, keeps running, and dispatches a
     subsequent unrelated packet afterward.

No feature is migrated here -- these tests exercise only the
correlation mechanism, never login/history/lookup/etc., since none of
those exist as request/response packets yet.

Run with:
    pytest tests/test_request_registry.py -v
"""

import socket
import threading
import time

import pytest

from client.session import ClientSession
from utils.network import receive_message, send_message
from utils.request_registry import PendingRequestRegistry, RequestTimeoutError

# ----------------------------------------------------------------------
# 1. PendingRequestRegistry in isolation
# ----------------------------------------------------------------------


def test_new_request_id_is_unique():
    registry = PendingRequestRegistry()

    ids = {registry.new_request_id() for _ in range(1000)}

    assert len(ids) == 1000


def test_register_then_resolve_then_wait_returns_the_response():
    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()

    registry.register(request_id)
    resolved = registry.resolve(request_id, {"type": "x_result", "value": 42})

    assert resolved is True
    assert registry.wait(request_id, timeout=1.0) == {
        "type": "x_result",
        "value": 42,
    }


def test_wait_blocks_until_resolve_is_called_from_another_thread():
    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()
    registry.register(request_id)

    result = {}

    def waiter():
        result["response"] = registry.wait(request_id, timeout=2.0)

    thread = threading.Thread(target=waiter)
    thread.start()

    # Give the waiter a moment to actually be blocked in wait() before
    # resolving -- proves this is real blocking, not a race that only
    # passes because resolve() happened to run first.
    time.sleep(0.1)
    assert thread.is_alive(), "waiter returned before resolve() was called"

    registry.resolve(request_id, {"type": "done"})
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert result["response"] == {"type": "done"}


def test_double_register_same_id_raises():
    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()
    registry.register(request_id)

    with pytest.raises(ValueError):
        registry.register(request_id)


def test_resolve_with_no_matching_pending_request_returns_false():
    registry = PendingRequestRegistry()

    assert registry.resolve("nobody-is-waiting-for-this", {"type": "x"}) is False


def test_resolve_with_none_request_id_returns_false():
    """Every packet type that existed before D1 has no request_id at
    all -- resolve(None, ...) must be a safe, cheap no-op so the
    handle_packet() hook can call it unconditionally on every packet."""
    registry = PendingRequestRegistry()

    assert registry.resolve(None, {"type": "chat"}) is False


def test_wait_without_register_raises_key_error():
    registry = PendingRequestRegistry()

    with pytest.raises(KeyError):
        registry.wait("never-registered", timeout=0.1)


def test_wait_times_out_and_raises_request_timeout_error():
    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()
    registry.register(request_id)

    start = time.monotonic()
    with pytest.raises(RequestTimeoutError):
        registry.wait(request_id, timeout=0.1)
    elapsed = time.monotonic() - start

    assert elapsed < 1.0, "wait() took far longer than the requested timeout"


def test_timed_out_request_is_removed_and_a_late_resolve_is_ignored():
    """A response that arrives after the caller has already given up
    must not raise, corrupt state, or resolve some future unrelated
    request that happens to reuse... anything -- it simply finds
    nothing registered."""
    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()
    registry.register(request_id)

    with pytest.raises(RequestTimeoutError):
        registry.wait(request_id, timeout=0.05)

    assert registry.pending_count() == 0

    late_resolve = registry.resolve(request_id, {"type": "too-late"})
    assert late_resolve is False


def test_cancel_removes_a_pending_entry_without_raising():
    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()
    registry.register(request_id)

    registry.cancel(request_id)

    assert registry.pending_count() == 0
    with pytest.raises(KeyError):
        registry.wait(request_id, timeout=0.05)


def test_cancel_on_unknown_id_is_a_no_op():
    registry = PendingRequestRegistry()

    registry.cancel("was-never-registered")  # must not raise


def test_concurrent_requests_each_receive_their_own_response_only():
    """The core correctness property of the whole mechanism: N
    concurrently in-flight requests, resolved in a deliberately
    scrambled order, must each unblock with exactly their own
    response -- never another request's."""
    registry = PendingRequestRegistry()
    request_count = 25
    request_ids = [registry.new_request_id() for _ in range(request_count)]

    for request_id in request_ids:
        registry.register(request_id)

    results = {}
    errors = []

    def waiter(request_id):
        try:
            results[request_id] = registry.wait(request_id, timeout=5.0)
        except Exception as error:  # noqa: BLE001 -- captured for the
            # test's own assertion below, not swallowed; a thread
            # exception here must fail the test, not vanish silently.
            errors.append((request_id, error))

    threads = [
        threading.Thread(target=waiter, args=(rid,)) for rid in request_ids
    ]
    for thread in threads:
        thread.start()

    # Resolve in reverse order, deliberately not the order they were
    # registered/started in.
    for request_id in reversed(request_ids):
        registry.resolve(request_id, {"type": "x_result", "id": request_id})

    for thread in threads:
        thread.join(timeout=5.0)

    assert not errors, errors
    assert len(results) == request_count
    for request_id in request_ids:
        assert results[request_id] == {"type": "x_result", "id": request_id}


def test_pending_count_reflects_in_flight_requests():
    registry = PendingRequestRegistry()

    assert registry.pending_count() == 0

    a = registry.new_request_id()
    b = registry.new_request_id()
    registry.register(a)
    registry.register(b)
    assert registry.pending_count() == 2

    registry.resolve(a, {})
    registry.wait(a, timeout=1.0)
    assert registry.pending_count() == 1

    registry.cancel(b)
    assert registry.pending_count() == 0


# ----------------------------------------------------------------------
# 2. ClientSession.send_request() / handle_packet() wiring
# ----------------------------------------------------------------------
#
# A real connected socket pair stands in for the TLS connection --
# send_request() calls the genuine utils.network.send_message() on it,
# so what actually goes out on the wire is inspected exactly as the
# real receiver thread would see it. No mocking of ClientSession
# itself.


def _make_connected_session():
    """A bare ClientSession wired to one end of a real socket pair;
    the test drives the other end, standing in for the server."""
    session = ClientSession()
    client_sock, server_sock = socket.socketpair()
    session.client_socket = client_sock
    session.connected = True
    return session, server_sock


def test_send_request_puts_a_request_id_on_the_wire():
    session, server_sock = _make_connected_session()
    try:
        thread = threading.Thread(
            target=session.send_request,
            args=({"type": "ping"},),
            kwargs={"timeout": 2.0},
        )
        thread.start()

        sent = receive_message(server_sock)
        assert sent["type"] == "ping"
        assert sent.get("request_id")

        # Unblock the waiting thread so it doesn't leak past the test.
        session.handle_packet({"type": "pong", "request_id": sent["request_id"]})
        thread.join(timeout=2.0)
        assert not thread.is_alive()
    finally:
        server_sock.close()


def test_send_request_returns_the_correlated_response():
    session, server_sock = _make_connected_session()
    try:
        result = {}

        def do_request():
            result["response"] = session.send_request(
                {"type": "ping"}, timeout=2.0
            )

        thread = threading.Thread(target=do_request)
        thread.start()

        sent = receive_message(server_sock)
        response = {
            "type": "pong",
            "request_id": sent["request_id"],
            "value": "hello",
        }
        session.handle_packet(response)

        thread.join(timeout=2.0)
        assert not thread.is_alive()
        assert result["response"] == response
    finally:
        server_sock.close()


def test_original_packet_dict_passed_in_is_not_mutated():
    """send_request() must operate on its own copy -- mutating the
    caller's dict in place would be a surprising side effect for
    anything that reuses the same packet object afterward."""
    session, server_sock = _make_connected_session()
    try:
        original = {"type": "ping"}

        thread = threading.Thread(
            target=session.send_request, args=(original,), kwargs={"timeout": 2.0}
        )
        thread.start()

        sent = receive_message(server_sock)
        session.handle_packet({"type": "pong", "request_id": sent["request_id"]})
        thread.join(timeout=2.0)

        assert original == {"type": "ping"}
    finally:
        server_sock.close()


def test_send_request_times_out_when_no_response_arrives():
    session, server_sock = _make_connected_session()
    try:
        start = time.monotonic()
        with pytest.raises(RequestTimeoutError):
            session.send_request({"type": "ping"}, timeout=0.2)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0
        assert session._pending_requests.pending_count() == 0

        # The request still genuinely went out -- only the reply never
        # came -- confirming this is a real timeout, not a send failure.
        sent = receive_message(server_sock)
        assert sent["type"] == "ping"
    finally:
        server_sock.close()


def test_unrelated_incoming_packet_is_dispatched_normally_during_a_pending_request():
    """An incoming packet with no request_id (every packet type before
    D1) must still reach its normal handler while a request is
    in-flight, and must not resolve or otherwise disturb that
    request."""
    session, server_sock = _make_connected_session()
    try:
        thread = threading.Thread(
            target=session.send_request, args=({"type": "ping"},), kwargs={"timeout": 2.0}
        )
        thread.start()

        sent = receive_message(server_sock)
        request_id = sent["request_id"]

        # An ordinary, unrelated notification arrives first --
        # handle_user_list() updates session.online_users directly
        # (and emits users_updated), so this is a real, observable
        # side effect of normal dispatch, not a mock expectation.
        session.handle_packet({"type": "user_list", "users": ["alice", "bob"]})

        assert session.online_users == ["alice", "bob"], (
            "unrelated packet was not dispatched through the normal path"
        )
        assert session._pending_requests.pending_count() == 1, (
            "the unrelated packet incorrectly resolved the pending request"
        )

        # Now the real response arrives and the request completes normally.
        session.handle_packet({"type": "pong", "request_id": request_id})
        thread.join(timeout=2.0)
        assert not thread.is_alive()
    finally:
        server_sock.close()


def test_response_with_unknown_request_id_falls_through_without_raising():
    """A packet that happens to carry a request_id matching nothing
    pending (e.g. a stale/duplicate delivery) must not crash
    handle_packet() -- it falls through to normal type-based dispatch
    like anything else, and an unhandled type is silently ignored,
    exactly as it already is today."""
    session, server_sock = _make_connected_session()
    try:
        session.handle_packet(
            {"type": "totally_unhandled_type", "request_id": "no-one-is-waiting"}
        )  # must not raise
    finally:
        server_sock.close()


def test_concurrent_send_requests_from_multiple_threads_get_their_own_reply():
    session, server_sock = _make_connected_session()
    try:
        request_count = 8
        results = [None] * request_count
        errors = []

        def do_request(index):
            try:
                results[index] = session.send_request(
                    {"type": "ping", "index": index}, timeout=5.0
                )
            except Exception as error:  # noqa: BLE001 -- captured for
                # this test's own assertion, not silently discarded.
                errors.append((index, error))

        threads = [
            threading.Thread(target=do_request, args=(i,))
            for i in range(request_count)
        ]
        for thread in threads:
            thread.start()

        # Drain all N outgoing requests, then resolve them in reverse
        # order -- deliberately not the order they were sent in.
        sent_packets = [receive_message(server_sock) for _ in range(request_count)]
        for sent in reversed(sent_packets):
            session.handle_packet(
                {
                    "type": "pong",
                    "request_id": sent["request_id"],
                    "echo_index": sent["index"],
                }
            )

        for thread in threads:
            thread.join(timeout=5.0)

        assert not errors, errors
        for index in range(request_count):
            assert results[index]["echo_index"] == index
    finally:
        server_sock.close()


def test_send_failure_cancels_the_pending_registration():
    """If the socket write itself fails, nothing should be left
    registered waiting for a response that can now never arrive."""
    session, server_sock = _make_connected_session()
    try:
        session.client_socket.close()  # sendall() on this will now raise

        with pytest.raises(OSError):
            session.send_request({"type": "ping"}, timeout=1.0)

        assert session._pending_requests.pending_count() == 0
    finally:
        server_sock.close()


# ----------------------------------------------------------------------
# 3. The real receiver thread -- not handle_packet() called directly
# ----------------------------------------------------------------------


def test_real_receiver_thread_resolves_request_and_keeps_dispatching():
    """
    Starts the actual background thread ClientSession.start_receiver()
    spawns in production (client.receiver.receive_messages(), reading
    real socket data in a loop) and drives the whole path an end user
    would hit: a requesting thread blocked in send_request(), a test
    peer standing in for the server sending the correlated response
    over the socket, and -- the point of this test -- a second,
    unrelated packet sent afterward to prove the receiver thread is
    still alive and still dispatching normally, not stalled or killed
    by having just resolved a pending request.
    """

    session, peer_sock = _make_connected_session()
    try:
        session.start_receiver()
        assert session.receiver_thread is not None

        # --- send_request() from a separate thread, resolved by the
        # real receiver thread reading the peer's reply ---

        result = {}

        def do_request():
            result["response"] = session.send_request(
                {"type": "ping"}, timeout=5.0
            )

        requester = threading.Thread(target=do_request)
        requester.start()

        # The REAL receiver thread reads this, not the test thread.
        sent = receive_message(peer_sock)
        assert sent["type"] == "ping"
        request_id = sent["request_id"]

        send_message(
            peer_sock,
            {"type": "pong", "request_id": request_id, "value": "ok"},
        )

        requester.join(timeout=5.0)
        assert not requester.is_alive(), "send_request() never returned"
        assert result["response"] == {
            "type": "pong",
            "request_id": request_id,
            "value": "ok",
        }

        # --- the receiver thread must still be running, and must
        # still dispatch a subsequent, unrelated packet normally ---

        assert session.receiver_thread.is_alive(), (
            "receiver thread exited after resolving a correlated request"
        )

        send_message(peer_sock, {"type": "user_list", "users": ["alice", "bob"]})

        deadline = time.monotonic() + 2.0
        while session.online_users != ["alice", "bob"] and time.monotonic() < deadline:
            time.sleep(0.01)

        assert session.online_users == ["alice", "bob"], (
            "receiver thread stopped dispatching packets after resolving "
            "the request"
        )
        assert session.receiver_thread.is_alive()
    finally:
        # Clean shutdown: closing the peer end makes the receiver
        # thread's blocking recv() return EOF, which
        # client/receiver.py's own loop already treats as "Server
        # disconnected" and exits on -- no special-casing needed here.
        peer_sock.close()
        session.receiver_thread.join(timeout=2.0)
        assert not session.receiver_thread.is_alive(), (
            "receiver thread failed to stop after the peer closed"
        )
