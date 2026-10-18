
import os
import socket
import struct
import threading
from pathlib import Path

from crypto_utils import encrypt_message, decrypt_message

HOST = "127.0.0.1"
PORT = 5000
MAX_MESSAGE_SIZE = 65536


def load_key():
    """Load the pre-shared AES key from the local .env file."""
    env_file = Path(__file__).resolve().parent / ".env"

    if not env_file.exists():
        raise FileNotFoundError("Missing .env file")

    for line in env_file.read_text().splitlines():
        if line.startswith("CHAT_KEY="):
            key_hex = line.split("=", 1)[1].strip()
            key = bytes.fromhex(key_hex)

            if len(key) != 32:
                raise ValueError("CHAT_KEY must be 32 bytes")

            return key

    raise ValueError("CHAT_KEY not found in .env")


def receive_exact(sock, length):
    """Receive exactly the requested number of bytes."""
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Server disconnected")

        data.extend(chunk)

    return bytes(data)


def receive_messages(sock, key):
    """Receive and decrypt messages from other clients."""
    try:
        while True:
            header = receive_exact(sock, 4)
            length = struct.unpack("!I", header)[0]

            if not 28 <= length <= MAX_MESSAGE_SIZE:
                raise ValueError("Invalid message size")

            encrypted = receive_exact(sock, length)

            try:
                message = decrypt_message(encrypted, key)
                print(f"\nReceived: {message}")
                print("You: ", end="", flush=True)
            except Exception:
                print("\nUnable to decrypt message.")

    except (ConnectionError, OSError, ValueError):
        print("\nDisconnected from server.")


def start_client():
    key = load_key()

    username = input("Enter your chat name: ").strip()

    if not username:
        username = "Anonymous"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((HOST, PORT))

        print("Connected to encrypted chat server!")
        print("Type /quit to exit.")

        receiver = threading.Thread(
            target=receive_messages,
            args=(sock, key),
            daemon=True
        )
        receiver.start()

        while True:
            message = input("You: ")

            if message.lower() == "/quit":
                break

            if not message.strip():
                continue

            plaintext = f"{username}: {message}"
            encrypted = encrypt_message(plaintext, key)

            if len(encrypted) > MAX_MESSAGE_SIZE:
                print("Message too long.")
                continue

            packet = struct.pack("!I", len(encrypted)) + encrypted
            sock.sendall(packet)

    except (ConnectionRefusedError, ConnectionError, OSError) as error:
        print(f"Connection error: {error}")

    finally:
        sock.close()
        print("Chat closed.")


if __name__ == "__main__":
    start_client()
