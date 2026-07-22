"""
Multi-Client Chat Client with Usernames
"""

import socket
import threading

from config import HOST, PORT, BUFFER_SIZE, ENCODING


def receive_messages(client_socket):
    """
    Receive messages from the server.
    """
    while True:
        try:
            message = client_socket.recv(BUFFER_SIZE).decode(ENCODING)

            print(f"\n{message}")
            print("You: ", end="", flush=True)

        except:
            print("\nDisconnected from server.")
            break


def start_client():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((HOST, PORT))

    print("=" * 50)
    print(" Secure Communication Client")
    print("=" * 50)

    # Ask for username
    username = input("Enter your username: ")

    # Send username to server
    client_socket.send(username.encode(ENCODING))

    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket,),
        daemon=True
    )

    receive_thread.start()

    while True:

        message = input("You: ")

        if message.lower() == "exit":
            break

        client_socket.send(message.encode(ENCODING))

    client_socket.close()


if __name__ == "__main__":
    start_client()