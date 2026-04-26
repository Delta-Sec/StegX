from __future__ import annotations

import os
from typing import List, Sequence, Tuple

from .exceptions import InsufficientSharesError

_LOG = [0] * 256
_EXP = [0] * 512
_a = 1
for _i in range(255):
    _EXP[_i] = _a
    _LOG[_a] = _i
    _a <<= 1
    if _a & 0x100:
        _a ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]

def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]

def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b] + 255) % 255]

def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = gf_mul(acc, x) ^ c
    return acc

def split_secret(secret: bytes, k: int, n: int) -> List[bytes]:
    if not (1 <= k <= n <= 255):
        raise ValueError("Require 1 <= k <= n <= 255 for Shamir over GF(256)")
    if not secret:
        raise ValueError("Secret must be non-empty")

    shares: List[bytearray] = [bytearray([i + 1, k]) for i in range(n)]
    for byte in secret:
        coeffs = [byte] + list(os.urandom(k - 1))
        for i in range(n):
            shares[i].append(_eval_poly(coeffs, i + 1))
    return [bytes(s) for s in shares]

def combine_shares(shares: Sequence[bytes]) -> bytes:
    if len(shares) < 1:
        raise ValueError("Need at least one share to read the threshold")
    if len(shares[0]) < 3:
        raise ValueError("Share too short — expected [x][k][y…] format")
    k_required = shares[0][1]
    if k_required < 2:
        raise ValueError(f"Share header encodes an invalid threshold ({k_required} < 2)")
    if len(shares) < k_required:
        raise InsufficientSharesError(
            f"Need at least {k_required} shares to reconstruct the secret "
            f"(only {len(shares)} provided)"
        )
    xs = []
    ys_per_byte: List[List[int]] = []
    secret_len = len(shares[0]) - 2
    for s in shares:
        if len(s) != secret_len + 2:
            raise ValueError("Shares have inconsistent length")
        if s[0] == 0:
            raise ValueError("Share has invalid x-coordinate 0")
        if s[1] != k_required:
            raise ValueError(
                f"Shares have inconsistent threshold: expected {k_required}, got {s[1]}"
            )
        xs.append(s[0])
    if len(set(xs)) != len(xs):
        raise ValueError("Shares must have distinct x-coordinates")

    for byte_idx in range(secret_len):
        ys_per_byte.append([s[2 + byte_idx] for s in shares])

    secret = bytearray(secret_len)
    for byte_idx in range(secret_len):
        secret[byte_idx] = _lagrange_at_zero(xs, ys_per_byte[byte_idx])
    return bytes(secret)

def _lagrange_at_zero(xs: Sequence[int], ys: Sequence[int]) -> int:
    acc = 0
    m = len(xs)
    for i in range(m):
        num = 1
        den = 1
        for j in range(m):
            if i == j:
                continue
            num = gf_mul(num, xs[j])
            den = gf_mul(den, xs[j] ^ xs[i])
        term = gf_mul(ys[i], gf_div(num, den))
        acc ^= term
    return acc

def encode_share(share: bytes) -> bytes:
    if len(share) < 3:
        raise ValueError("share too short")
    return share

def decode_share(buf: bytes) -> Tuple[int, int, bytes]:
    if len(buf) < 3:
        raise ValueError("share too short")
    return buf[0], buf[1], buf[2:]
