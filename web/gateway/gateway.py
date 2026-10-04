"""
Web Gateway (Phase 15 -- Web Interoperability, Stage 1).

A browser cannot open the raw TCP socket the existing desktop
protocol requires (see docs/architecture/web_interoperability.md).
This gateway is the minimum bridge that makes the EXISTING server
reachable from a browser without changing the server, the wire
protocol, or the cryptographic architecture at all:

    Browser (WebSocket, wss://)
        |
        v
    THIS GATEWAY  (one asyncio task per browser connection)
        |  opens its own ordinary TLS+TCP connection to the real
        |  server, using the SAME security.tls.build_client_context()
        |  and the SAME utils.network.send_message()/receive_message()
        |  framing every existing desktop client already uses --
        |  nothing here is a second protocol implementation.
        v
    Existing server (server/server.py, completely unmodified)

Trust boundary (critical -- see docs/architecture/web_interoperability.md
for the full write-up): this gateway is a TRANSPORT bridge only. It
re-frames already-opaque JSON packets between a WebSocket text frame
and the existing 4-byte-length-prefixed TCP frame -- it never inspects,
decrypts, decodes, or modifies a packet's cryptographic fields
(ciphertext, signatures, encapsulations, wrapped keys). Exactly like
the existing server itself, it is a relay: end-to-end confidentiality
and authenticity remain entirely between the two ClientSession-
equivalent endpoints (a desktop ClientSession and this repo's web
client), never something this process could break even if compromised,
because it never possesses any session/group AES key, any ML-DSA
private key, or any ML-KEM/RSA private key -- those never leave the
browser or the desktop client in the first place.

A malformed WebSocket text frame (not valid JSON) or an oversized
frame is rejected here, before ever reaching the existing TCP
protocol -- the existing server never sees it. Frame-size limits reuse
config.MAX_FRAME_BYTES, the same limit the existing TCP protocol
already enforces (D8 / L-2), rather than inventing a second one.

Usage:
    python -m web.gateway.gateway
    python -m web.gateway.gateway --host 0.0.0.0 --port 8765
"""

import argparse
import asyncio
import json
import socket
import sys
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import websockets
from websockets.exceptions import ConnectionClosed

from config import HANDSHAKE_TIMEOUT_SECONDS, MAX_FRAME_BYTES, SERVER_HOST, SERVER_PORT
from logger_config import setup_logger
from security.tls import build_client_context
from utils.network import FrameStalledError, FrameTooLargeError, receive_message, send_message

DEFAULT_GATEWAY_HOST = "127.0.0.1"
DEFAULT_GATEWAY_PORT = 8765

logger = setup_logger("gateway_logger", "gateway.log")


def _open_tls_connection_to_server():
    """
    Open one TLS+TCP connection to the existing server -- the exact
    same sequence ClientSession.connect() already performs (client/
    session.py), duplicated only because this is a standalone process
    with no ClientSession instance to reuse. Uses the SAME
    security.tls.build_client_context(), the SAME SERVER_HOST/
    SERVER_PORT, and the SAME certificate verification -- there is no
    second, weaker TLS path for browser-originated traffic.
    """

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
    raw_socket.connect((SERVER_HOST, SERVER_PORT))

    tls_context = build_client_context()

    try:
        tls_socket = tls_context.wrap_socket(raw_socket, server_hostname=SERVER_HOST)
    except Exception:
        raw_socket.close()
        raise

    tls_socket.settimeout(None)

    return tls_socket


def _tcp_reader_thread(tcp_socket, loop, queue, stop_event):
    """
    Runs on a background thread (blocking socket I/O, exactly like the
    desktop client's own receiver thread -- client/receiver.py) and
    hands each received packet to the asyncio side via a thread-safe
    queue push. Never touches the WebSocket object directly -- only
    the event loop's queue, which is what call_soon_threadsafe is for.
    """

    try:
        while not stop_event.is_set():
            try:
                packet = receive_message(tcp_socket, allow_idle=True)
            except (FrameStalledError, FrameTooLargeError, OSError):
                break

            if packet is None:
                break

            loop.call_soon_threadsafe(queue.put_nowait, packet)
    finally:
        loop.call_soon_threadsafe(queue.put_nowait, None)


async def _pump_tcp_to_websocket(websocket, queue):
    while True:
        packet = await queue.get()

        if packet is None:
            return

        try:
            await websocket.send(json.dumps(packet))
        except ConnectionClosed:
            return


async def _pump_websocket_to_tcp(websocket, tcp_socket):
    async for raw_text in websocket:

        if not isinstance(raw_text, str):
            # Binary WebSocket frames carry no meaning in this
            # protocol (every existing packet type is JSON text) --
            # rejecting rather than guessing keeps this gateway from
            # ever inventing a second wire representation.
            logger.warning("Rejected a non-text WebSocket frame.")
            continue

        try:
            packet = json.loads(raw_text)
        except json.JSONDecodeError:
            logger.warning("Rejected a malformed (non-JSON) WebSocket frame.")
            continue

        if not isinstance(packet, dict):
            logger.warning("Rejected a WebSocket frame that was not a JSON object.")
            continue

        try:
            await asyncio.to_thread(send_message, tcp_socket, packet)
        except (FrameTooLargeError, OSError) as error:
            logger.warning(f"Failed to relay a browser packet to the server: {error}")
            return


async def handle_browser_connection(websocket):
    peer = getattr(websocket, "remote_address", None)
    logger.info(f"Browser connected: {peer}")

    try:
        tcp_socket = await asyncio.to_thread(_open_tls_connection_to_server)
    except Exception as error:
        logger.warning(f"Could not reach the existing server for {peer}: {error}")
        await websocket.close(code=1011, reason="Upstream server unreachable")
        return

    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()
    stop_event = threading.Event()

    reader_thread = threading.Thread(
        target=_tcp_reader_thread,
        args=(tcp_socket, loop, queue, stop_event),
        daemon=True,
    )
    reader_thread.start()

    try:
        await asyncio.gather(
            _pump_tcp_to_websocket(websocket, queue),
            _pump_websocket_to_tcp(websocket, tcp_socket),
        )
    except ConnectionClosed:
        pass
    finally:
        stop_event.set()

        try:
            tcp_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        tcp_socket.close()

        logger.info(f"Browser disconnected: {peer}")


async def _serve(host, port):
    async with websockets.serve(
        handle_browser_connection,
        host,
        port,
        max_size=MAX_FRAME_BYTES,
    ):
        logger.info(f"Web gateway listening on ws://{host}:{port}")
        print(f"Web gateway listening on ws://{host}:{port} -> {SERVER_HOST}:{SERVER_PORT} (TLS)")
        await asyncio.Future()


def main():
    parser = argparse.ArgumentParser(
        description="WebSocket-to-existing-server gateway (Phase 15)."
    )
    parser.add_argument("--host", default=DEFAULT_GATEWAY_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_GATEWAY_PORT)
    args = parser.parse_args()

    asyncio.run(_serve(args.host, args.port))


if __name__ == "__main__":
    main()
