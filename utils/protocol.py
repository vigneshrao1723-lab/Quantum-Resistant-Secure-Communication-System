"""
Communication Protocol Utilities

This module defines the JSON packet format used by the
Quantum-Resistant Secure Communication System.
"""

import json


def create_chat_packet(username, message):
    """
    Create a chat message packet.

    Returns:
        JSON string
    """
    packet = {
        "type": "chat",
        "username": username,
        "message": message
    }

    return json.dumps(packet)


def create_join_packet(username):
    """
    Create a join notification packet.
    """
    packet = {
        "type": "join",
        "username": username
    }

    return json.dumps(packet)


def create_leave_packet(username):
    """
    Create a leave notification packet.
    """
    packet = {
        "type": "leave",
        "username": username
    }

    return json.dumps(packet)


def parse_packet(packet):
    """
    Convert a JSON packet back into a Python dictionary.
    """
    return json.loads(packet)