from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import (
    HEADER_SALT_LEN,
    HEADER_SIZE_V2,
    HEADER_SIZE_V3_BASE,
    YK_CHALLENGE_NONCE_LEN,
)
from .header import (
    FLAG_DUAL_CIPHER,
    FLAG_KEYFILE,
    FLAG_YUBIKEY,
    NONCE_LEN,
    SALT_LEN,
    Header,
)
from .kdf import (
    HKDF_INFO_AES,
    HKDF_INFO_CHACHA,
    KdfParams,
    derive_master_key,
    hkdf_subkey,
)
from .exceptions import AuthenticationFailure, CorruptedPayload
from .fips import ban_if_fips
from .secure_memory import SecureBuffer

LEGACY_SALT_SIZE = 16
LEGACY_NONCE_SIZE = 12
LEGACY_KEY_SIZE = 32
LEGACY_PBKDF2_ITERATIONS = 390_000

@dataclass
class EncryptOptions:
    kdf_params: KdfParams
    dual_cipher: bool = False
    keyfile_bytes: Optional[bytes] = None
    yubikey_response: Optional[bytes] = None
    base_flags: int = 0

    yk_challenge_nonce: Optional[bytes] = field(default=None)

    header_salt: Optional[bytes] = field(default=None)

    @classmethod
    def default(cls, dual_cipher: bool = False, keyfile_bytes: Optional[bytes] = None) -> "EncryptOptions":
        return cls(
            kdf_params=KdfParams.default_argon2id(),
            dual_cipher=dual_cipher,
            keyfile_bytes=keyfile_bytes,
        )

def encrypt_data(inner_plaintext: bytes, password: str, options: EncryptOptions) -> bytes:
    if not isinstance(inner_plaintext, bytes):
        raise TypeError("inner_plaintext must be bytes")
    if not password:
        raise ValueError("Password cannot be empty.")


    if options.dual_cipher:
        ban_if_fips("ChaCha20-Poly1305 (dual-cipher)")

    salt = os.urandom(SALT_LEN)
    aes_nonce = os.urandom(NONCE_LEN)
    chacha_nonce = os.urandom(NONCE_LEN) if options.dual_cipher else b"\x00" * NONCE_LEN


    header_salt = options.header_salt if options.header_salt is not None else os.urandom(HEADER_SALT_LEN)


    yk_nonce = options.yk_challenge_nonce or b"\x00" * YK_CHALLENGE_NONCE_LEN

    flags = options.base_flags
    if options.dual_cipher:
        flags |= FLAG_DUAL_CIPHER
    if options.keyfile_bytes:
        flags |= FLAG_KEYFILE
    if options.yubikey_response:
        flags |= FLAG_YUBIKEY

    master_sb = SecureBuffer(
        data=derive_master_key(
            password,
            salt,
            options.kdf_params,
            options.keyfile_bytes,
            options.yubikey_response,
            header_salt=header_salt,
        )
    )
    aes_sb: Optional[SecureBuffer] = None
    chacha_sb: Optional[SecureBuffer] = None
    try:
        aes_sb = SecureBuffer(
            data=hkdf_subkey(bytes(master_sb.buffer), HKDF_INFO_AES, length=32)
        )
        if options.dual_cipher:
            chacha_sb = SecureBuffer(
                data=hkdf_subkey(bytes(master_sb.buffer), HKDF_INFO_CHACHA, length=32)
            )


        header_draft = Header(
            kdf=options.kdf_params,
            flags=flags,
            salt=salt,
            aes_nonce=aes_nonce,
            chacha_nonce=chacha_nonce,
            inner_ct_length=0,
            header_salt=header_salt,
            yk_challenge_nonce=yk_nonce,
            kms_wrap=b"",
        )

        aes = AESGCM(bytes(aes_sb.buffer))
        aad = header_draft.as_aad()
        ciphertext = aes.encrypt(aes_nonce, inner_plaintext, aad)

        if options.dual_cipher and chacha_sb is not None:
            chacha = ChaCha20Poly1305(bytes(chacha_sb.buffer))
            ciphertext = chacha.encrypt(chacha_nonce, ciphertext, aad)

        header_draft.inner_ct_length = len(ciphertext)
        final_header = header_draft.pack()

        logging.debug(
            "StegX v3 encryption: kdf=0x%02x dual_cipher=%s keyfile=%s payload=%d B ct=%d B",
            options.kdf_params.kdf_id,
            options.dual_cipher,
            bool(options.keyfile_bytes),
            len(inner_plaintext),
            len(ciphertext),
        )
        return final_header + ciphertext
    finally:
        master_sb.close()
        if aes_sb is not None:
            aes_sb.close()
        if chacha_sb is not None:
            chacha_sb.close()

def decrypt_data(
    encrypted_stream: bytes,
    password: str,
    keyfile_bytes: Optional[bytes] = None,
    yubikey_response: Optional[bytes] = None,
) -> bytes:
    if not isinstance(encrypted_stream, bytes):
        raise TypeError("encrypted_stream must be bytes")
    if not password:
        raise ValueError("Password cannot be empty.")


    if len(encrypted_stream) < 2:
        raise CorruptedPayload("Encrypted stream too short to contain header.")
    version = encrypted_stream[1]
    if version == 0x02:
        min_header_bytes = HEADER_SIZE_V2
    elif version == 0x03:
        min_header_bytes = HEADER_SIZE_V3_BASE
    else:
        raise CorruptedPayload(f"Unsupported StegX version in stream: 0x{version:02x}")

    if len(encrypted_stream) < min_header_bytes:
        raise CorruptedPayload("Encrypted stream too short to contain header.")

    try:
        header = Header.unpack(encrypted_stream)
    except ValueError as e:
        raise CorruptedPayload(f"Container header rejected: {e}") from e

    ct_start = header.packed_size
    ct_end = ct_start + header.inner_ct_length
    if ct_end > len(encrypted_stream):
        raise CorruptedPayload("Encrypted stream truncated: inner ciphertext length exceeds buffer.")
    ciphertext = encrypted_stream[ct_start:ct_end]


    if header.has(FLAG_DUAL_CIPHER):
        ban_if_fips("ChaCha20-Poly1305 (dual-cipher) decrypt")
    if header.has(FLAG_YUBIKEY):


        ban_if_fips("YubiKey HMAC-SHA1 (decrypt)")

    needs_keyfile = header.has(FLAG_KEYFILE)
    if needs_keyfile and not keyfile_bytes:
        raise ValueError("This payload was sealed with a keyfile; none was provided.")
    if not needs_keyfile and keyfile_bytes:
        logging.debug("Keyfile supplied but header has no keyfile flag; ignoring.")
        keyfile_bytes = None

    needs_yk = header.has(FLAG_YUBIKEY)
    if needs_yk and not yubikey_response:
        raise ValueError(
            "This payload was sealed with a YubiKey factor; no response was provided."
        )
    if not needs_yk and yubikey_response:
        logging.debug("YubiKey response supplied but header has no yubikey flag; ignoring.")
        yubikey_response = None

    master_sb = SecureBuffer(
        data=derive_master_key(
            password,
            header.salt,
            header.kdf,
            keyfile_bytes,
            yubikey_response,
            header_salt=header.header_salt,
        )
    )
    aes_sb: Optional[SecureBuffer] = None
    chacha_sb: Optional[SecureBuffer] = None
    try:
        aes_sb = SecureBuffer(
            data=hkdf_subkey(bytes(master_sb.buffer), HKDF_INFO_AES, length=32)
        )
        if header.has(FLAG_DUAL_CIPHER):
            chacha_sb = SecureBuffer(
                data=hkdf_subkey(bytes(master_sb.buffer), HKDF_INFO_CHACHA, length=32)
            )

        aad = header.as_aad()
        try:
            if header.has(FLAG_DUAL_CIPHER) and chacha_sb is not None:
                chacha = ChaCha20Poly1305(bytes(chacha_sb.buffer))
                ciphertext = chacha.decrypt(header.chacha_nonce, ciphertext, aad)
            aes = AESGCM(bytes(aes_sb.buffer))
            plaintext = aes.decrypt(header.aes_nonce, ciphertext, aad)
        except InvalidTag as e:
            raise AuthenticationFailure(
                "Wrong password, wrong keyfile, wrong YubiKey, or header tampering."
            ) from e
        return plaintext
    finally:
        master_sb.close()
        if aes_sb is not None:
            aes_sb.close()
        if chacha_sb is not None:
            chacha_sb.close()

def decrypt_legacy_v1(encrypted_payload: bytes, password: str) -> bytes:
    header_size = LEGACY_SALT_SIZE + LEGACY_NONCE_SIZE
    if len(encrypted_payload) < header_size:
        raise ValueError("Legacy payload too short.")
    salt = encrypted_payload[:LEGACY_SALT_SIZE]
    nonce = encrypted_payload[LEGACY_SALT_SIZE:header_size]
    ciphertext = encrypted_payload[header_size:]

    with SecureBuffer(data=_legacy_derive_key(password, salt)) as key:
        aes = AESGCM(bytes(key))
        try:
            return aes.decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            raise AuthenticationFailure("Legacy v1 authentication failed.") from e

def _legacy_derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=LEGACY_KEY_SIZE,
        salt=salt,
        iterations=LEGACY_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

__all__ = [
    "EncryptOptions",
    "InvalidTag",
    "decrypt_data",
    "decrypt_legacy_v1",
    "encrypt_data",
]
