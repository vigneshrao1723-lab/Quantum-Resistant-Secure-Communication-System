"""
Phase 19 -- Mobile Client.

A genuine, protocol-compatible client of the existing server (real
TLS+TCP socket, real 4-byte-length-prefixed framing, real ML-KEM-768/
ML-DSA-65/AES-256-GCM) -- not a simplified or bridged reimplementation.
Unlike the web client (which needs web/gateway/gateway.py because a
browser cannot open a raw TCP socket), this client is Python, so it
talks to the server directly, exactly like client/session.py does,
reusing the SAME crypto/protocol/storage modules unchanged rather than
porting them. See docs/architecture/mobile_client.md for the full
architecture writeup.
"""
