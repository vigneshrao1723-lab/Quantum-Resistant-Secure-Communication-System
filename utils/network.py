"""
Network Utilities

Provides reliable send/receive functions using
length-prefixed TCP messages.
"""

import json
import struct


def send_message(sock, message):
    """
    Send a JSON packet with a 4-byte length prefix.
    """

    # Convert dictionary to JSON string
    if isinstance(message, dict):
        message = json.dumps(message)

    data = message.encode("utf-8")

    length = struct.pack("!I", len(data))

    sock.sendall(length + data)


def receive_message(sock):
    """
    Receive a complete JSON packet.

    Returns:
        dict, string or None
    """

    header = recvall(sock, 4)

    if not header:
        return None

    length = struct.unpack("!I", header)[0]

    data = recvall(sock, length)

    if not data:
        return None

    message = data.decode("utf-8")

    # Try to convert JSON back into a dictionary
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        # Username and other plain strings remain strings
        return message


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