
import os
from crypto_utils import encrypt_message, decrypt_message

# Generate a temporary AES-256 key for testing
key = os.urandom(32)

# Original message
message = "Hello! This is my encrypted chat app."

print("Original message:", message)

# Encrypt the message
encrypted = encrypt_message(message, key)
print("Encrypted message:", encrypted.hex())

# Decrypt the message
decrypted = decrypt_message(encrypted, key)
print("Decrypted message:", decrypted)

# Verify the results
assert decrypted == message
print("Encryption and decryption successful!")
