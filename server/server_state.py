"""
Server State

Stores shared resources used by the server.
"""

from datetime import datetime, timezone

from logger_config import setup_logger


def _utc_now():
    """Current UTC time as a naive datetime, via the non-deprecated
    timezone-aware API. See auth/authentication_service.py's identical
    helper for the full rationale.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ServerState:
    """
    Stores all shared server resources.
    """

    def __init__(self):

        # Connected clients
        #
        # Format:
        # {
        #     client_socket: {
        #         "username": "...",
        #         "user_id": "...",
        #         "session_id": "...",
        #         "algorithm": "RSA",
        #         "public_key": "...",
        #         "connected_at": datetime(...)
        #     }
        # }
        self.clients = {}

        # Logger
        self.logger = setup_logger(
            "server_logger",
            "server.log"
        )

    def add_client(self, client_socket, username, user_id=None, session_id=None):
        """
        Add a newly connected, authenticated client.
        """

        self.clients[client_socket] = {
            "username": username,
            "user_id": user_id,
            "session_id": session_id,
            "algorithm": None,
            "public_key": None,
            # Protocol-Level ML-DSA Origin Authentication: opaque,
            # already-base64-encoded strings, relayed verbatim by
            # distribute_public_keys() exactly like "public_key"
            # itself -- the server never decodes, verifies, or
            # interprets either one. Verification is entirely the
            # RECEIVING client's job (client/session.py::
            # _handle_signed_public_key()); the server remains a dumb,
            # non-verifying relay, unchanged from every other packet
            # type it forwards.
            "signing_public_key": None,
            "identity_signature": None,
            # Phase 18.5: client-claimed, unverified -- see
            # set_public_key()'s own docstring for why this is a
            # deliberately separate key from "device_id" (set only by
            # a verified device_session_bind()).
            "announced_device_id": None,
            "connected_at": _utc_now()
        }

    def remove_client(self, client_socket):
        """
        Remove a disconnected client.
        """

        if client_socket in self.clients:
            del self.clients[client_socket]

    def set_public_key(self,
                       client_socket,
                       algorithm,
                       public_key,
                       signing_public_key=None,
                       identity_signature=None,
                       device_id=None):
        """
        Store a client's public key.

        ``signing_public_key``/``identity_signature`` (Protocol-Level
        ML-DSA Origin Authentication): optional and additive, stored
        and later relayed exactly as received -- see the module
        docstring above. None (the default) for a legacy, unsigned
        key_exchange packet, unchanged from before this phase.

        ``device_id`` (Phase 16D -- Device-Aware Peer Identity):
        optional and additive, stored and later relayed exactly as
        received, same as the two fields above -- purely transport
        metadata identifying WHICH of the sender's devices this
        identity belongs to; the server never interprets or trusts it
        for anything itself (see client/session.py::
        _peer_identity_key()). None for every pre-existing caller.

        Phase 18.5 -- Closure Audit: stored under ``announced_device_id``,
        a DELIBERATELY SEPARATE dict key from ``device_id``. This value
        is entirely client-claimed (relayed verbatim off an ordinary
        key_exchange/public_key packet, which any authenticated
        connection can send at any time) and MUST NEVER be confused
        with ``device_id``, which server/device_handler.py::
        handle_device_session_bind() sets only after verifying a real
        ML-DSA signature proving possession of that exact device's
        private key -- and which is_device_bound_and_authorized()/
        _find_socket_for_bound_device()/handle_device_key_sync() then
        trust for security-relevant routing/authorization decisions.
        Before this rename both writes landed in the SAME "device_id"
        slot, so a later, unrelated, unverified key_exchange packet
        could silently overwrite (clobber) an already-verified device
        binding -- discovered during the Phase 18.5 same-account
        multi-device routing audit. Fixed by giving the unverified
        value its own name; nothing security-relevant ever reads it.
        """

        if client_socket in self.clients:

            self.clients[client_socket]["algorithm"] = algorithm

            self.clients[client_socket]["public_key"] = public_key

            self.clients[client_socket]["signing_public_key"] = signing_public_key

            self.clients[client_socket]["identity_signature"] = identity_signature

            self.clients[client_socket]["announced_device_id"] = device_id

    def get_username(self, client_socket):
        """
        Return the username for a client.
        """

        if client_socket in self.clients:
            return self.clients[client_socket]["username"]

        return None

    def get_client(self, client_socket):
        """
        Return the complete client information.
        """

        return self.clients.get(client_socket)