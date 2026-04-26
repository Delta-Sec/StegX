from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .constants import (
    ARGON2_MAX_MEMORY_KIB,
    ARGON2_MAX_PARALLELISM,
    ARGON2_MAX_TIME_COST,
    ARGON2_MIN_MEMORY_KIB,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_TIME_COST,
    FORMAT_VERSION_V2,
    FORMAT_VERSION_V3,
    HEADER_SALT_LEN,
    HEADER_SIZE_V2,
    HEADER_SIZE_V3_BASE,
    KMS_WRAP_MAX,
    PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
    YK_CHALLENGE_NONCE_LEN,
)
from .exceptions import HeaderParameterOutOfRange
from .kdf import KDF_ARGON2ID, KDF_PBKDF2, KdfParams

MAGIC = 0x58


VERSION = FORMAT_VERSION_V2
VERSION_V2 = FORMAT_VERSION_V2
VERSION_V3 = FORMAT_VERSION_V3

FLAG_COMPRESSED = 1 << 0
FLAG_DUAL_CIPHER = 1 << 1
FLAG_KEYFILE = 1 << 2
FLAG_ADAPTIVE = 1 << 3
FLAG_MATRIX = 1 << 4
FLAG_YUBIKEY = 1 << 5


HEADER_SIZE = HEADER_SIZE_V2
SALT_LEN = 16
NONCE_LEN = 12
KDF_PARAMS_LEN = 8

_STRUCT_V2 = struct.Struct(">BBBB8s16s12s12sI")
assert _STRUCT_V2.size == HEADER_SIZE_V2


_STRUCT_V3 = struct.Struct(">BBBB8s16s12s12sI16s16sH")
assert _STRUCT_V3.size == HEADER_SIZE_V3_BASE

def _check_argon2_params(time_cost: int, memory_cost: int, parallelism: int) -> None:
    if not (ARGON2_MIN_TIME_COST <= time_cost <= ARGON2_MAX_TIME_COST):
        raise HeaderParameterOutOfRange("Header rejected: KDF parameters out of range")
    if not (ARGON2_MIN_MEMORY_KIB <= memory_cost <= ARGON2_MAX_MEMORY_KIB):
        raise HeaderParameterOutOfRange("Header rejected: KDF parameters out of range")
    if not (ARGON2_MIN_PARALLELISM <= parallelism <= ARGON2_MAX_PARALLELISM):
        raise HeaderParameterOutOfRange("Header rejected: KDF parameters out of range")

@dataclass
class Header:
    kdf: KdfParams
    flags: int
    salt: bytes
    aes_nonce: bytes
    chacha_nonce: bytes = field(default_factory=lambda: b"\x00" * NONCE_LEN)
    inner_ct_length: int = 0

    header_salt: Optional[bytes] = None
    yk_challenge_nonce: Optional[bytes] = None
    kms_wrap: bytes = b""


    def has(self, flag: int) -> bool:
        return bool(self.flags & flag)

    @property
    def is_v3(self) -> bool:
        return self.header_salt is not None

    @property
    def packed_size(self) -> int:
        if self.is_v3:
            return HEADER_SIZE_V3_BASE + len(self.kms_wrap)
        return HEADER_SIZE_V2


    def pack(self) -> bytes:
        if self.is_v3:
            return self._pack_v3()
        return self._pack_v2()

    def _pack_v2(self) -> bytes:
        if len(self.salt) != SALT_LEN:
            raise ValueError("salt must be 16 bytes")
        if len(self.aes_nonce) != NONCE_LEN:
            raise ValueError("aes_nonce must be 12 bytes")
        if len(self.chacha_nonce) != NONCE_LEN:
            raise ValueError("chacha_nonce must be 12 bytes")
        return _STRUCT_V2.pack(
            MAGIC,
            VERSION_V2,
            self.kdf.kdf_id,
            self.flags & 0xFF,
            self._pack_kdf_params(),
            self.salt,
            self.aes_nonce,
            self.chacha_nonce,
            self.inner_ct_length & 0xFFFFFFFF,
        )

    def _pack_v3(self) -> bytes:
        if len(self.salt) != SALT_LEN:
            raise ValueError("salt must be 16 bytes")
        if len(self.aes_nonce) != NONCE_LEN:
            raise ValueError("aes_nonce must be 12 bytes")
        if len(self.chacha_nonce) != NONCE_LEN:
            raise ValueError("chacha_nonce must be 12 bytes")
        header_salt = self.header_salt or b"\x00" * HEADER_SALT_LEN
        yk_nonce = self.yk_challenge_nonce or b"\x00" * YK_CHALLENGE_NONCE_LEN
        if len(header_salt) != HEADER_SALT_LEN:
            raise ValueError("header_salt must be 16 bytes")
        if len(yk_nonce) != YK_CHALLENGE_NONCE_LEN:
            raise ValueError("yk_challenge_nonce must be 16 bytes")
        kms_wrap_len = len(self.kms_wrap)
        if kms_wrap_len > KMS_WRAP_MAX:


            raise ValueError(
                f"kms_wrap too large ({kms_wrap_len} B > {KMS_WRAP_MAX} B)"
            )
        base = _STRUCT_V3.pack(
            MAGIC,
            VERSION_V3,
            self.kdf.kdf_id,
            self.flags & 0xFF,
            self._pack_kdf_params(),
            self.salt,
            self.aes_nonce,
            self.chacha_nonce,
            self.inner_ct_length & 0xFFFFFFFF,
            header_salt,
            yk_nonce,
            kms_wrap_len,
        )
        return base + self.kms_wrap

    def _pack_kdf_params(self) -> bytes:
        if self.kdf.kdf_id == KDF_ARGON2ID:
            if not (1 <= self.kdf.time_cost <= 255):
                raise ValueError("Argon2 time_cost out of range")
            if not (1 <= self.kdf.parallelism <= 255):
                raise ValueError("Argon2 parallelism out of range")
            return struct.pack(">BIB2x", self.kdf.time_cost, self.kdf.memory_cost_kib, self.kdf.parallelism)
        if self.kdf.kdf_id == KDF_PBKDF2:
            return struct.pack(">I4x", self.kdf.iterations)
        raise ValueError(f"Unknown kdf_id: 0x{self.kdf.kdf_id:02x}")


    @classmethod
    def unpack(cls, buf: bytes) -> "Header":
        if len(buf) < 2:
            raise ValueError("Header too short")
        magic = buf[0]
        version = buf[1]
        if magic != MAGIC:
            raise ValueError("Header magic mismatch")
        if version == VERSION_V2:
            return cls._unpack_v2(buf)
        if version == VERSION_V3:
            return cls._unpack_v3(buf)
        raise ValueError(f"Unsupported StegX payload version: 0x{version:02x}")

    @classmethod
    def _unpack_v2(cls, buf: bytes) -> "Header":
        if len(buf) < HEADER_SIZE_V2:
            raise ValueError("v2 header too short")
        _, _, kdf_id, flags, kdf_blob, salt, aes_nonce, chacha_nonce, inner_len = \
            _STRUCT_V2.unpack(buf[:HEADER_SIZE_V2])
        kdf_params = cls._parse_kdf(kdf_id, kdf_blob)
        return cls(
            kdf=kdf_params,
            flags=flags,
            salt=salt,
            aes_nonce=aes_nonce,
            chacha_nonce=chacha_nonce,
            inner_ct_length=inner_len,
            header_salt=None,
            yk_challenge_nonce=None,
            kms_wrap=b"",
        )

    @classmethod
    def _unpack_v3(cls, buf: bytes) -> "Header":
        if len(buf) < HEADER_SIZE_V3_BASE:
            raise ValueError("v3 header too short")
        (_, _, kdf_id, flags, kdf_blob, salt, aes_nonce, chacha_nonce,
         inner_len, header_salt, yk_nonce, kms_wrap_len) = \
            _STRUCT_V3.unpack(buf[:HEADER_SIZE_V3_BASE])
        if kms_wrap_len > KMS_WRAP_MAX:


            raise HeaderParameterOutOfRange(
                "Header rejected: kms_wrap_len exceeds policy maximum"
            )
        kdf_params = cls._parse_kdf(kdf_id, kdf_blob)
        kms_wrap = buf[HEADER_SIZE_V3_BASE:HEADER_SIZE_V3_BASE + kms_wrap_len]
        if len(kms_wrap) != kms_wrap_len:
            raise ValueError("v3 header truncated: kms_wrap shorter than declared")
        return cls(
            kdf=kdf_params,
            flags=flags,
            salt=salt,
            aes_nonce=aes_nonce,
            chacha_nonce=chacha_nonce,
            inner_ct_length=inner_len,
            header_salt=header_salt,
            yk_challenge_nonce=yk_nonce,
            kms_wrap=kms_wrap,
        )

    @staticmethod
    def _parse_kdf(kdf_id: int, kdf_blob: bytes) -> KdfParams:
        if kdf_id == KDF_ARGON2ID:
            time_cost, memory_cost, parallelism = struct.unpack(">BIB2x", kdf_blob)
            _check_argon2_params(time_cost, memory_cost, parallelism)
            return KdfParams(
                kdf_id=KDF_ARGON2ID,
                time_cost=time_cost,
                memory_cost_kib=memory_cost,
                parallelism=parallelism,
            )
        if kdf_id == KDF_PBKDF2:
            (iterations,) = struct.unpack(">I4x", kdf_blob)
            if not (PBKDF2_MIN_ITERATIONS <= iterations <= PBKDF2_MAX_ITERATIONS):
                raise HeaderParameterOutOfRange("Header rejected: KDF parameters out of range")
            return KdfParams(kdf_id=KDF_PBKDF2, iterations=iterations)
        raise ValueError(f"Unknown kdf_id in header: 0x{kdf_id:02x}")


    def as_aad(self) -> bytes:
        saved = self.inner_ct_length
        self.inner_ct_length = 0
        try:
            return self.pack()
        finally:
            self.inner_ct_length = saved
