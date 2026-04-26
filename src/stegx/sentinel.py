from __future__ import annotations

import hashlib
import hmac
from typing import Tuple

from PIL import Image

SENTINEL_LEN = 16
SENTINEL_BITS = SENTINEL_LEN * 8

def cover_fingerprint(image: Image.Image) -> bytes:
    width, height = image.size
    mode = image.mode.encode("ascii")
    return hashlib.sha256(
        b"stegx/v2/cover\x00"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x00"
        + mode
    ).digest()

def derive_sentinel(sentinel_key: bytes, fingerprint: bytes) -> bytes:
    if len(sentinel_key) < 16:
        raise ValueError("sentinel_key too short")
    mac = hmac.new(sentinel_key, fingerprint, hashlib.sha256).digest()
    return mac[:SENTINEL_LEN]

def bytes_to_bits(data: bytes) -> str:
    return "".join(format(b, "08b") for b in data)

def bits_match_sentinel(bits: str, sentinel: bytes) -> bool:
    if len(bits) != SENTINEL_BITS:
        return False
    observed = _bits_to_bytes(bits)
    return hmac.compare_digest(observed, sentinel)

def _bits_to_bytes(bits: str) -> bytes:
    out = bytearray(len(bits) // 8)
    for i in range(len(out)):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (1 if bits[i * 8 + j] == "1" else 0)
        out[i] = byte
    return bytes(out)

def sentinel_bit_length() -> int:
    return SENTINEL_BITS

def derive_from_cover(sentinel_key: bytes, image: Image.Image) -> Tuple[bytes, str]:
    sentinel = derive_sentinel(sentinel_key, cover_fingerprint(image))
    return sentinel, bytes_to_bits(sentinel)
