"""
Receiver Module

Handles all incoming messages from the server.
"""

from utils.network import receive_message
from utils.protocol import parse_packet


def receive_messages(session):
    """
    Continuously receive messages from the server.

    Failures are handled at two different levels:

    Connection-level (socket closed/reset, or a failure while
    reading the length-prefixed frame itself): the underlying TCP
    byte stream can no longer be trusted to be in sync, so the
    receiver loop ends.

    Packet-level (a single malformed, malicious, or unhandleable
    packet -- e.g. a failed AES-GCM authentication check, a missing
    field, an unknown packet type): a complete frame was already
    read successfully, so the byte stream is still in sync. The
    failure is isolated to that one packet -- logged and surfaced
    to the GUI via session.error_occurred -- and the loop continues
    so the connection survives instead of dying on one bad packet.
    """

    while session.connected:

        try:
            data = receive_message(session.client_socket)

        except (ConnectionResetError, OSError) as error:

            session.logger.info(
                f"Connection closed while receiving: {error}"
            )

            break

        if data is None:

            session.logger.info(
                "Server disconnected."
            )

            break

        # --------------------------------------------------------
        # A complete frame was read successfully. Anything that
        # goes wrong from this point on is scoped to this single
        # packet and must not tear down the connection.
        # --------------------------------------------------------

        try:

            packet = parse_packet(data)

            session.handle_packet(packet)

        except Exception as error:

            session.logger.exception(
                f"Skipping malformed or unhandled packet: {error}"
            )

            session.error_occurred.emit(
                "Received an invalid packet and skipped it."
            )

            continue

    # --------------------------------------------------------------
    # The loop has ended. If it ended because of a connection
    # failure (session.connected is still True at this point)
    # rather than an explicit session.disconnect() call (which
    # already sets connected = False and emits connection_changed
    # itself), reflect the lost connection so the GUI updates.
    # --------------------------------------------------------------

    if session.connected:

        session.connected = False

        session.connection_changed.emit(False)

    session.logger.info(
        "Receiver thread stopped."
    )