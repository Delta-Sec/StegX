from __future__ import annotations

import logging
import struct as _struct
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as _CryptoHMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .fips import ban_if_fips


_TAG_PASSWORD = b"PWD0"
_TAG_KEYFILE = b"KFL0"
_TAG_YUBIKEY = b"YKR0"


_MAX_FACTOR_LEN = 16 * 1024 * 1024

KDF_ARGON2ID = 0x02
KDF_PBKDF2 = 0x01

MASTER_KEY_LEN = 32

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_PARALLELISM = 4

PBKDF2_ITERATIONS = 600_000

HKDF_INFO_AES = b"stegx/v2/aes-256-gcm"
HKDF_INFO_CHACHA = b"stegx/v2/chacha20-poly1305"
HKDF_INFO_SEED = b"stegx/v2/pixel-shuffle-seed"
HKDF_INFO_SENTINEL = b"stegx/v2/sentinel"
HKDF_INFO_DECOY_SEED = b"stegx/v2/decoy-shuffle-seed"

@dataclass(frozen=True)
class KdfParams:
    kdf_id: int
    time_cost: int = 0
    memory_cost_kib: int = 0
    parallelism: int = 0
    iterations: int = 0

    @classmethod
    def default_argon2id(cls) -> "KdfParams":
        return cls(
            kdf_id=KDF_ARGON2ID,
            time_cost=ARGON2_TIME_COST,
            memory_cost_kib=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
        )

    @classmethod
    def default_pbkdf2(cls) -> "KdfParams":
        return cls(kdf_id=KDF_PBKDF2, iterations=PBKDF2_ITERATIONS)

def _frame_factor(tag: bytes, data: bytes) -> bytes:
    if len(tag) != 4:
        raise ValueError("Factor tag must be exactly 4 bytes.")
    if len(data) > _MAX_FACTOR_LEN:
        raise ValueError(
            f"Factor '{tag.decode('ascii', 'replace')}' exceeds maximum "
            f"size of {_MAX_FACTOR_LEN} bytes."
        )
    return tag + _struct.pack("!I", len(data)) + data

def _mix_factors(
    password: bytes,
    keyfile_bytes: Optional[bytes],
    yubikey_response: Optional[bytes] = None,
) -> bytes:
    return (
        _frame_factor(_TAG_PASSWORD, password)
        + _frame_factor(_TAG_KEYFILE, keyfile_bytes or b"")
        + _frame_factor(_TAG_YUBIKEY, yubikey_response or b"")
    )

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    mac = _CryptoHMAC(salt, hashes.SHA256())
    mac.update(ikm)
    return mac.finalize()

def derive_master_key(
    password: str,
    salt: bytes,
    params: KdfParams,
    keyfile_bytes: Optional[bytes] = None,
    yubikey_response: Optional[bytes] = None,
    *,
    header_salt: Optional[bytes] = None,
) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")

    mixed = _mix_factors(password.encode("utf-8"), keyfile_bytes, yubikey_response)

    if header_salt is not None:
        mixed = hkdf_extract(salt=header_salt, ikm=mixed)

    if params.kdf_id == KDF_ARGON2ID:


        ban_if_fips("Argon2id KDF")
        return hash_secret_raw(
            secret=mixed,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost_kib,
            parallelism=params.parallelism,
            hash_len=MASTER_KEY_LEN,
            type=Type.ID,
        )

    if params.kdf_id == KDF_PBKDF2:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=MASTER_KEY_LEN,
            salt=salt,
            iterations=params.iterations,
        )
        return kdf.derive(mixed)

    raise ValueError(f"Unknown KDF id: 0x{params.kdf_id:02x}")

def hkdf_subkey(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    if len(master_key) != MASTER_KEY_LEN:
        raise ValueError(
            f"Master key must be exactly {MASTER_KEY_LEN} bytes "
            f"(got {len(master_key)})."
        )
    expander = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return expander.derive(master_key)

def seed_int_from_subkey(subkey: bytes) -> int:
    if len(subkey) < 8:
        raise ValueError("Sub-key too short to derive seed.")
    return int.from_bytes(subkey[:8], "big")

def derive_legacy_seed_from_password(password: str) -> int:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=8,
        salt=b"stegx_pixel_shuffle_v1",
        iterations=390_000,
    )
    key = kdf.derive(password.encode("utf-8"))
    return int.from_bytes(key, "big")

def calibrate_argon2_for_target_ms(target_ms: int = 500) -> KdfParams:
    import time

    ban_if_fips("Argon2id calibration")
    test_salt = b"\x00" * 16
    params = KdfParams.default_argon2id()
    for memory_kib in (32_768, 65_536, 131_072, 262_144):
        t0 = time.perf_counter()
        hash_secret_raw(
            secret=b"calibration",
            salt=test_salt,
            time_cost=params.time_cost,
            memory_cost=memory_kib,
            parallelism=params.parallelism,
            hash_len=32,
            type=Type.ID,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logging.debug("Argon2id calibration: memory=%d KiB took %.1f ms", memory_kib, elapsed_ms)
        if elapsed_ms >= target_ms:
            return KdfParams(
                kdf_id=KDF_ARGON2ID,
                time_cost=params.time_cost,
                memory_cost_kib=memory_kib,
                parallelism=params.parallelism,
            )
    return params
