"""
Protocol Module

Defines all packet formats used by the application.
"""


def create_auth_packet(access_token):
    """
    Create an authentication request packet carrying the
    client's JWT access token.
    """

    return {
        "type": "auth",
        "access_token": access_token
    }


def create_auth_result_packet(
    success,
    message,
    username=None
):
    """
    Create a packet reporting the outcome of server-side
    JWT authentication.
    """

    return {
        "type": "auth_result",
        "success": success,
        "message": message,
        "username": username
    }


def create_chat_packet(
    sender,
    receiver,
    message
):
    """
    Create a private chat message packet.
    """

    return {
        "type": "chat",
        "sender": sender,
        "receiver": receiver,
        "message": message
    }


def create_join_packet(username):
    """
    Create a user joined packet.
    """

    return {
        "type": "join",
        "username": username
    }


def create_leave_packet(username):
    """
    Create a user left packet.
    """

    return {
        "type": "leave",
        "username": username
    }


def create_user_list_packet(users):
    """
    Create a packet containing the current
    online users.
    """

    return {
        "type": "user_list",
        "users": users
    }


def create_public_key_packet(
    username,
    algorithm,
    public_key
):
    """
    Create a public key exchange packet.
    """

    return {
        "type": "key_exchange",
        "operation": "public_key",
        "algorithm": algorithm,
        "username": username,
        "public_key": public_key
    }


def create_session_key_packet(
    sender,
    receiver,
    algorithm,
    encrypted_key
):
    """
    Create an encrypted AES session key packet.
    """

    return {
        "type": "key_exchange",
        "operation": "session_key",
        "algorithm": algorithm,
        "sender": sender,
        "receiver": receiver,
        "encrypted_key": encrypted_key
    }


def parse_packet(packet):
    """
    Return the packet as-is.

    All packets are already Python dictionaries after
    receive_message(), so no parsing is required.
    """

    return packet