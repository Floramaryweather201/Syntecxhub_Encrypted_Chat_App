
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(message, key):
    """Encrypt a message using AES-256-GCM."""
    aes = AESGCM(key)

    # Generate a fresh 12-byte nonce for each message
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce + ciphertext


def decrypt_message(encrypted_data, key):
    """Decrypt and authenticate an encrypted message."""
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")
