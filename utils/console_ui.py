"""
Console UI Utilities

Provides a centralized interface for all
console output used by the chat client.
"""

from threading import Lock

_console_lock = Lock()


def divider():
    """
    Print a divider.
    """

    print("=" * 40)


def display_online_users(session):
    """
    Display all currently online users.
    """

    with _console_lock:

        print()

        divider()
        print("           ONLINE USERS")
        divider()

        if not session.online_users:

            print("No users online.")

        else:

            for index, user in enumerate(
                session.online_users,
                start=1
            ):

                print(f"{index}. {user}")

        divider()
        print()


def display_system(message):
    """
    Display a system message.
    """

    with _console_lock:

        print(f"\n[INFO] {message}")


def display_warning(message):
    """
    Display a warning.
    """

    with _console_lock:

        print(f"\n[WARNING] {message}")


def display_error(message):
    """
    Display an error.
    """

    with _console_lock:

        print(f"\n[ERROR] {message}")


def display_chat(sender, message):
    """
    Display an incoming chat message.
    """

    with _console_lock:

        print()
        print(f"{sender}: {message}")
        print()


def display_help():
    """
    Display available commands.
    """

    with _console_lock:

        print()

        divider()
        print("AVAILABLE COMMANDS")
        divider()

        print("/users   Show online users")
        print("/switch  Switch conversation")
        print("/stats   Session information")
        print("/help    Show commands")
        print("exit     Disconnect")

        divider()
        print()


def display_stats(session):
    """
    Display session statistics.
    """

    with _console_lock:

        print()

        divider()
        print("SESSION INFORMATION")
        divider()

        print(f"Username      : {session.username}")
        print(f"Current Chat  : {session.current_chat}")
        print("Encryption    : AES-256")
        print("Key Exchange  : RSA-2048")
        print(
            f"Online Users  : "
            f"{len(session.online_users)}"
        )

        divider()
        print()


def prompt(session):
    """
    Display the chat prompt.

    If a chat partner has been selected,
    show it in the prompt.
    """

    with _console_lock:

        if session.current_chat:

            print(
                f"[{session.username} → "
                f"{session.current_chat}] You: ",
                end="",
                flush=True
            )

        else:

            print(
                f"[{session.username}] You: ",
                end="",
                flush=True
            )