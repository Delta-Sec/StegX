# -*- coding: utf-8 -*-

"""AES Encryption and Decryption Functions for StegX using cryptography library."""

import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Constants
SALT_SIZE = 16  # Size of the salt in bytes
NONCE_SIZE = 12 # Recommended nonce size for AES-GCM (96 bits)
KEY_SIZE = 32   # AES-256 key size in bytes
PBKDF2_ITERATIONS = 390000 # Recommended minimum iterations for PBKDF2

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password and salt using PBKDF2HMAC-SHA256."""
    if not isinstance(password, bytes):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    logging.debug(f"Derived key using salt: {salt.hex()}")
    return key

def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypts data using AES-256-GCM with a key derived from the password.

    Args:
        data: The plaintext data to encrypt (bytes).
        password: The password to derive the encryption key from (str).

    Returns:
        The encrypted data formatted as: salt + nonce + ciphertext + tag (bytes).
        The tag is appended automatically by AESGCM.encrypt.

    Raises:
        TypeError: If input data is not bytes or password is not str.
        Exception: For underlying cryptography errors.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data to encrypt must be bytes.")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        # 1. Generate a random salt
        salt = os.urandom(SALT_SIZE)
        logging.debug(f"Generated salt: {salt.hex()}")

        # 2. Derive the encryption key
        key = derive_key(password, salt)
        logging.debug("Encryption key derived successfully.")

        # 3. Generate a random nonce
        nonce = os.urandom(NONCE_SIZE)
        logging.debug(f"Generated nonce: {nonce.hex()}")

        # 4. Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None) # No associated data
        logging.info(f"Encryption successful. Plaintext size: {len(data)}, Ciphertext size: {len(ciphertext)}")

        # 5. Prepend salt and nonce to the ciphertext
        encrypted_payload = salt + nonce + ciphertext
        logging.debug(f"Final encrypted payload size (salt+nonce+ciphertext): {len(encrypted_payload)}")

        return encrypted_payload

    except Exception as e:
        logging.exception("Encryption failed.")
        raise # Re-raise the exception after logging

def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    """Decrypts data encrypted with AES-256-GCM.

    Args:
        encrypted_payload: The encrypted data including salt, nonce, and ciphertext+tag (bytes).
        password: The password to derive the decryption key from (str).

    Returns:
        The original plaintext data (bytes).

    Raises:
        TypeError: If input data is not bytes or password is not str.
        ValueError: If the encrypted payload is too short or password is empty.
        InvalidTag: If decryption fails (likely due to incorrect password or corrupted data).
        Exception: For other underlying cryptography errors.
    """
    if not isinstance(encrypted_payload, bytes):
        raise TypeError("Encrypted payload must be bytes.")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty.")

    header_size = SALT_SIZE + NONCE_SIZE
    if len(encrypted_payload) < header_size:
        raise ValueError(f"Encrypted payload is too short. Minimum size required: {header_size} bytes.")

    try:
        # 1. Extract salt and nonce from the beginning
        salt = encrypted_payload[:SALT_SIZE]
        nonce = encrypted_payload[SALT_SIZE:header_size]
        ciphertext = encrypted_payload[header_size:]
        logging.debug(f"Extracted salt: {salt.hex()}")
        logging.debug(f"Extracted nonce: {nonce.hex()}")
        logging.debug(f"Ciphertext size (incl. tag): {len(ciphertext)}")

        # 2. Derive the decryption key using the extracted salt
        key = derive_key(password, salt)
        logging.debug("Decryption key derived successfully.")

        # 3. Decrypt using AES-GCM
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None) # No associated data
        logging.info(f"Decryption successful. Ciphertext size: {len(ciphertext)}, Plaintext size: {len(plaintext)}")

        return plaintext

    except InvalidTag:
        logging.error("Decryption failed: Invalid authentication tag. This usually means the password is incorrect or the data is corrupted.")
        raise InvalidTag("Decryption failed. Check password or data integrity.")
    except ValueError as e:
        # Catch specific value errors like empty password or short payload
        logging.error(f"Decryption failed due to value error: {e}")
        raise
    except Exception as e:
        logging.exception("Decryption failed due to an unexpected error.")
        raise # Re-raise the exception after logging

