
import socket
import threading
import logging
import struct

HOST = "127.0.0.1"
PORT = 5000
MAX_MESSAGE_SIZE = 65536

clients = set()
clients_lock = threading.Lock()

logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


def receive_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data.extend(chunk)

    return bytes(data)


def broadcast(message, sender):
    packet = struct.pack("!I", len(message)) + message

    with clients_lock:
        recipients = [
            client for client in clients
            if client != sender
        ]

    for client in recipients:
        try:
            client.sendall(packet)
        except OSError:
            with clients_lock:
                clients.discard(client)


def handle_client(client, address):
    print(f"Client connected: {address}")
    logging.info("Client connected: %s", address)

    try:
        while True:
            header = receive_exact(client, 4)
            message_length = struct.unpack("!I", header)[0]

            if not 28 <= message_length <= MAX_MESSAGE_SIZE:
                raise ValueError("Invalid encrypted message size")

            encrypted_message = receive_exact(
                client, message_length
            )
            logging.info(
                "Encrypted message received from %s (%d bytes)",
                address,
                len(encrypted_message)
            )
            
            broadcast(encrypted_message, client)

    except (OSError, ConnectionError, ValueError):
        pass

    finally:
        with clients_lock:
            clients.discard(client)

        client.close()
        print(f"Client disconnected: {address}")
        logging.info("Client disconnected: %s", address)


def start_server():
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen()

    print(f"Encrypted chat server listening on {HOST}:{PORT}")

    try:
        while True:
            client, address = server.accept()

            with clients_lock:
                clients.add(client)

            thread = threading.Thread(
                target=handle_client,
                args=(client, address),
                daemon=True
            )

            thread.start()

    except KeyboardInterrupt:
        print("\nServer shutting down.")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
