import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 390000

def derive_key(password: str, salt: bytes) -> bytes:

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

    if not isinstance(data, bytes):
        raise TypeError("Data to encrypt must be bytes.")
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        salt = os.urandom(SALT_SIZE)
        logging.debug(f"Generated salt: {salt.hex()}")

        key = derive_key(password, salt)
        logging.debug("Encryption key derived successfully.")

        nonce = os.urandom(NONCE_SIZE)
        logging.debug(f"Generated nonce: {nonce.hex()}")

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        logging.info(f"Encryption successful. Plaintext size: {len(data)}, Ciphertext size: {len(ciphertext)}")

        encrypted_payload = salt + nonce + ciphertext
        logging.debug(f"Final encrypted payload size (salt+nonce+ciphertext): {len(encrypted_payload)}")

        return encrypted_payload

    except Exception as e:
        logging.exception(f"Encryption failed: {e}")
        raise

def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
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
        salt = encrypted_payload[:SALT_SIZE]
        nonce = encrypted_payload[SALT_SIZE:header_size]
        ciphertext = encrypted_payload[header_size:]
        logging.debug(f"Extracted salt: {salt.hex()}")
        logging.debug(f"Extracted nonce: {nonce.hex()}")
        logging.debug(f"Ciphertext size (incl. tag): {len(ciphertext)}")

        key = derive_key(password, salt)
        logging.debug("Decryption key derived successfully.")

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        logging.info(f"Decryption successful. Ciphertext size: {len(ciphertext)}, Plaintext size: {len(plaintext)}")

        return plaintext

    except InvalidTag:
        logging.error("Decryption failed: Invalid authentication tag."
                      " This usually means the password is incorrect or the data is corrupted.")
        raise InvalidTag("Decryption failed. Check password or data integrity.")
    except ValueError as e:
        logging.error(f"Decryption failed due to value error: {e}")
        raise
    except Exception as e:
        logging.exception(f"Decryption failed due to an unexpected error: {e}")
        raise
