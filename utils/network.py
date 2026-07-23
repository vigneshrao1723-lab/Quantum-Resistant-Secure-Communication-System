"""
Network Utilities

Provides reliable send/receive functions using
length-prefixed TCP messages.
"""

import struct


def send_message(sock, message):
    """
    Send a message with a 4-byte length prefix.
    """
    data = message.encode("utf-8")
    length = struct.pack("!I", len(data))  # 4-byte unsigned integer (network byte order)
    sock.sendall(length + data)


def receive_message(sock):
    """
    Receive a complete length-prefixed message.

    Returns:
        Decoded string, or None if the connection is closed.
    """
    # Read the 4-byte length header
    header = recvall(sock, 4)

    if not header:
        return None

    length = struct.unpack("!I", header)[0]

    # Read the actual message
    data = recvall(sock, length)

    if not data:
        return None

    return data.decode("utf-8")


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