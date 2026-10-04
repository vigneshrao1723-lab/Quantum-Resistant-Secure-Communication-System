"""
Standalone real TLS server bound to the fixed port (5000) the built APK
expects by default -- for physical Android device validation, where
`start_test_server()`'s ephemeral-port design (tests/tls_test_support.py)
doesn't fit: the phone dials whatever `config.SERVER_PORT` was baked into
the APK at build time, reached over `adb reverse tcp:5000 tcp:5000`.

Not a new server implementation -- reuses tests/tls_test_support.py's own
build_server_context()/serve_tls_client() plus server.client_handler.
handle_client(), the exact same real code path every other test in this
project already exercises. Only the port binding differs.
"""

import socket
import sys
import threading

sys.path.insert(0, ".")

from tests.tls_test_support import build_server_context, serve_tls_client
from server.client_handler import handle_client
from server.server_state import ServerState


def main():
    state = ServerState()
    context = build_server_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 5000))
    server_socket.listen()
    print("PHYSICAL_VALIDATION_SERVER_READY port=5000", flush=True)

    def _accept_loop():
        while True:
            client_socket, address = server_socket.accept()
            t = threading.Thread(
                target=serve_tls_client,
                args=(handle_client, state, client_socket, address),
                kwargs={"context": context},
                daemon=True,
            )
            t.start()

    _accept_loop()


if __name__ == "__main__":
    main()
