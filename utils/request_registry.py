"""
Request/Response Correlation (D1 -- Request/Response Infrastructure)

Framework-free, protocol-agnostic plumbing: a way for one thread to
send a packet and block waiting for its own specific reply, while a
SEPARATE thread (the client's receiver loop -- see client/receiver.py)
keeps reading and dispatching every other incoming packet as normal.

This module knows nothing about sockets, TLS, or any packet type --
it only correlates opaque ``request_id`` strings to whichever thread
is waiting on them. That separation is deliberate: the later phases
that actually move a feature (login, user lookup, history, ...) onto
a request/response packet pair reuse this unchanged; this phase adds
no new packet type and moves no feature.

Typical usage (see ClientSession.send_request() for the real wiring):

    registry = PendingRequestRegistry()
    request_id = registry.new_request_id()
    packet["request_id"] = request_id
    registry.register(request_id)
    send_message(sock, packet)                    # caller's own I/O
    response = registry.wait(request_id, timeout)  # blocks this thread

    # Meanwhile, on the receiver thread, for every incoming packet:
    if registry.resolve(packet.get("request_id"), packet):
        continue  # delivered to the waiting caller, not dispatched further
"""

import threading
import uuid


class RequestTimeoutError(Exception):
    """No response carrying the matching request_id arrived within
    the caller's timeout. The pending entry has already been removed
    by the time this is raised -- a response that arrives late finds
    no one waiting and is safely ignored (see resolve())."""


class PendingRequestRegistry:
    """
    Thread-safe correlation of outgoing requests to their eventual
    responses.

    One entry per in-flight request_id, holding a threading.Event and
    a slot for the response packet. register()/resolve()/wait()/
    cancel() only ever touch the dict under self._lock; the actual
    blocking in wait() happens on the per-request Event, never while
    holding the lock -- so unrelated requests, and resolve() calls for
    other request_ids, are never blocked by one caller's wait().
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._pending = {}

    @staticmethod
    def new_request_id():
        """A fresh, unguessable correlation id. UUID4 is used purely
        for uniqueness here -- it carries no meaning and is never
        parsed back."""
        return uuid.uuid4().hex

    def register(self, request_id):
        """
        Create the pending slot for ``request_id``. Must be called
        BEFORE the request packet is actually sent -- otherwise a
        response could theoretically arrive (on the receiver thread)
        before this thread starts waiting for it, and resolve() would
        find no one registered.
        """

        with self._lock:
            if request_id in self._pending:
                raise ValueError(
                    f"request_id already registered: {request_id}"
                )
            self._pending[request_id] = {
                "event": threading.Event(),
                "response": None,
            }

    def resolve(self, request_id, response_packet):
        """
        Deliver ``response_packet`` to whichever caller is waiting on
        ``request_id``, if any.

        Returns True if a pending request was found and resolved --
        the caller (the receiver thread) should treat the packet as
        fully consumed and not also dispatch it through the normal
        packet-type handling, since a correlated response is not an
        independent notification. Returns False for a request_id that
        is missing, unknown, or None (not every incoming packet is a
        response to something this client asked for) -- the caller
        should fall back to normal dispatch in that case.
        """

        if not request_id:
            return False

        with self._lock:
            entry = self._pending.get(request_id)
            if entry is None:
                return False
            entry["response"] = response_packet

        # set() outside the lock: waking the waiting thread never
        # needs to hold self._lock, and holding it here would only
        # block unrelated register()/resolve() calls pointlessly.
        entry["event"].set()
        return True

    def wait(self, request_id, timeout):
        """
        Block the calling thread until ``request_id``'s response
        arrives or ``timeout`` seconds elapse.

        Always removes the pending entry before returning, whether it
        resolved or timed out -- a response that arrives after a
        timeout has already been raised finds nothing registered and
        is silently ignored by resolve() (see its docstring), rather
        than being delivered to a caller that has already stopped
        waiting.
        """

        with self._lock:
            entry = self._pending.get(request_id)

        if entry is None:
            raise KeyError(
                f"No pending request registered for {request_id!r} -- "
                f"call register() before wait()."
            )

        received = entry["event"].wait(timeout)

        with self._lock:
            self._pending.pop(request_id, None)

        if not received:
            raise RequestTimeoutError(
                f"Timed out after {timeout}s waiting for a response to "
                f"request {request_id}"
            )

        return entry["response"]

    def cancel(self, request_id):
        """
        Remove a pending entry without waiting for it -- e.g. when
        sending the request itself failed, so no response will ever
        arrive and nothing should be left registered. A no-op if the
        id is already gone (already resolved, already timed out,
        or never registered).
        """

        with self._lock:
            self._pending.pop(request_id, None)

    def pending_count(self):
        """Number of requests currently awaiting a response. Exposed
        for tests and diagnostics, not used in any control flow."""

        with self._lock:
            return len(self._pending)
