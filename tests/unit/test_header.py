
import os

import pytest

from stegx.constants import (
    HEADER_SALT_LEN,
    HEADER_SIZE_V2,
    HEADER_SIZE_V3_BASE,
    KMS_WRAP_MAX,
    YK_CHALLENGE_NONCE_LEN,
)
from stegx.exceptions import HeaderParameterOutOfRange
from stegx.header import (
    FLAG_ADAPTIVE,
    FLAG_COMPRESSED,
    FLAG_DUAL_CIPHER,
    FLAG_KEYFILE,
    FLAG_MATRIX,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    VERSION_V2,
    VERSION_V3,
    Header,
)
from stegx.kdf import KDF_ARGON2ID, KDF_PBKDF2, KdfParams

def _argon_header(flags=0, inner_len=1024):
    return Header(
        kdf=KdfParams.default_argon2id(),
        flags=flags,
        salt=b"\x01" * 16,
        aes_nonce=b"\x02" * 12,
        chacha_nonce=b"\x03" * 12,
        inner_ct_length=inner_len,
    )

def test_pack_unpack_roundtrip_argon2id():
    h = _argon_header(flags=FLAG_COMPRESSED | FLAG_ADAPTIVE)
    blob = h.pack()
    assert len(blob) == HEADER_SIZE
    assert blob[0] == MAGIC
    assert blob[1] == VERSION
    parsed = Header.unpack(blob)
    assert parsed.kdf.kdf_id == KDF_ARGON2ID
    assert parsed.kdf.time_cost == h.kdf.time_cost
    assert parsed.kdf.memory_cost_kib == h.kdf.memory_cost_kib
    assert parsed.kdf.parallelism == h.kdf.parallelism
    assert parsed.flags == FLAG_COMPRESSED | FLAG_ADAPTIVE
    assert parsed.salt == h.salt
    assert parsed.aes_nonce == h.aes_nonce
    assert parsed.chacha_nonce == h.chacha_nonce
    assert parsed.inner_ct_length == h.inner_ct_length

def test_pack_unpack_roundtrip_pbkdf2():
    h = Header(
        kdf=KdfParams.default_pbkdf2(),
        flags=FLAG_DUAL_CIPHER | FLAG_KEYFILE | FLAG_MATRIX,
        salt=b"\xaa" * 16,
        aes_nonce=b"\xbb" * 12,
        chacha_nonce=b"\xcc" * 12,
        inner_ct_length=42,
    )
    parsed = Header.unpack(h.pack())
    assert parsed.kdf.kdf_id == KDF_PBKDF2
    assert parsed.kdf.iterations == h.kdf.iterations
    assert parsed.has(FLAG_DUAL_CIPHER)
    assert parsed.has(FLAG_KEYFILE)
    assert parsed.has(FLAG_MATRIX)

def test_unpack_rejects_bad_magic():
    h = _argon_header()
    blob = bytearray(h.pack())
    blob[0] ^= 0xFF
    with pytest.raises(ValueError):
        Header.unpack(bytes(blob))

def test_unpack_rejects_bad_version():
    h = _argon_header()
    blob = bytearray(h.pack())
    blob[1] = 0x09
    with pytest.raises(ValueError):
        Header.unpack(bytes(blob))

def test_pack_rejects_bad_salt_size():
    h = _argon_header()
    h.salt = b"short"
    with pytest.raises(ValueError):
        h.pack()

def test_as_aad_zeros_inner_length():
    h = _argon_header(inner_len=1024)
    aad = h.as_aad()
    assert aad[:52] == h.pack()[:52]

    assert aad[52:] == b"\x00\x00\x00\x00"

    assert h.inner_ct_length == 1024


def _v3_header(
    *,
    flags: int = 0,
    inner_len: int = 1024,
    header_salt: bytes = None,
    yk_nonce: bytes = None,
    kms_wrap: bytes = b"",
    kdf_params: KdfParams = None,
) -> Header:
    return Header(
        kdf=kdf_params or KdfParams.default_argon2id(),
        flags=flags,
        salt=b"\x11" * 16,
        aes_nonce=b"\x22" * 12,
        chacha_nonce=b"\x33" * 12,
        inner_ct_length=inner_len,
        header_salt=header_salt if header_salt is not None else b"\x44" * HEADER_SALT_LEN,
        yk_challenge_nonce=yk_nonce if yk_nonce is not None else b"\x55" * YK_CHALLENGE_NONCE_LEN,
        kms_wrap=kms_wrap,
    )

def test_v3_version_byte_and_base_size():
    h = _v3_header()
    blob = h.pack()
    assert blob[0] == MAGIC
    assert blob[1] == VERSION_V3
    assert len(blob) == HEADER_SIZE_V3_BASE

def test_v3_is_v3_flag():
    assert _v3_header().is_v3 is True
    v2 = _argon_header()
    assert v2.is_v3 is False

def test_v3_roundtrip_empty_kms_wrap():
    header_salt = os.urandom(HEADER_SALT_LEN)
    yk_nonce = os.urandom(YK_CHALLENGE_NONCE_LEN)
    h = _v3_header(
        flags=FLAG_COMPRESSED | FLAG_ADAPTIVE,
        header_salt=header_salt,
        yk_nonce=yk_nonce,
        kms_wrap=b"",
    )
    blob = h.pack()
    assert len(blob) == HEADER_SIZE_V3_BASE
    parsed = Header.unpack(blob)
    assert parsed.is_v3
    assert parsed.header_salt == header_salt
    assert parsed.yk_challenge_nonce == yk_nonce
    assert parsed.kms_wrap == b""
    assert parsed.packed_size == HEADER_SIZE_V3_BASE
    assert parsed.salt == h.salt
    assert parsed.aes_nonce == h.aes_nonce
    assert parsed.chacha_nonce == h.chacha_nonce
    assert parsed.flags == h.flags
    assert parsed.inner_ct_length == h.inner_ct_length

def test_v3_roundtrip_populated_kms_wrap():
    header_salt = os.urandom(HEADER_SALT_LEN)
    yk_nonce = os.urandom(YK_CHALLENGE_NONCE_LEN)
    wrap = os.urandom(257)
    h = _v3_header(header_salt=header_salt, yk_nonce=yk_nonce, kms_wrap=wrap)
    blob = h.pack()
    assert len(blob) == HEADER_SIZE_V3_BASE + len(wrap)
    parsed = Header.unpack(blob)
    assert parsed.header_salt == header_salt
    assert parsed.yk_challenge_nonce == yk_nonce
    assert parsed.kms_wrap == wrap
    assert parsed.packed_size == HEADER_SIZE_V3_BASE + len(wrap)

def test_v3_roundtrip_kms_wrap_at_max():
    wrap = os.urandom(KMS_WRAP_MAX)
    h = _v3_header(kms_wrap=wrap)
    blob = h.pack()
    parsed = Header.unpack(blob)
    assert parsed.kms_wrap == wrap
    assert len(parsed.kms_wrap) == KMS_WRAP_MAX

def test_v3_kms_wrap_len_field_big_endian():
    wrap_len = 0x0123
    assert wrap_len <= KMS_WRAP_MAX
    wrap = b"\xaa" * wrap_len
    blob = _v3_header(kms_wrap=wrap).pack()
    assert blob[88] == 0x01
    assert blob[89] == 0x23
    assert int.from_bytes(blob[88:90], "big") == wrap_len

    assert blob[HEADER_SIZE_V3_BASE : HEADER_SIZE_V3_BASE + wrap_len] == wrap

def test_v3_unpack_rejects_truncated_kms_wrap():
    h = _v3_header(kms_wrap=b"\xde\xad\xbe\xef" * 16)
    blob = bytearray(h.pack())
    truncated = bytes(blob[:HEADER_SIZE_V3_BASE + 10])
    with pytest.raises(ValueError, match="truncated|shorter"):
        Header.unpack(truncated)

def test_v3_unpack_too_short_for_base():
    blob = _v3_header().pack()[: HEADER_SIZE_V3_BASE - 1]
    with pytest.raises(ValueError):
        Header.unpack(blob)

def test_v3_pack_rejects_oversize_kms_wrap():
    h = _v3_header(kms_wrap=b"\x00" * (KMS_WRAP_MAX + 1))
    with pytest.raises(ValueError, match="too large|kms_wrap"):
        h.pack()

def test_v3_unpack_rejects_oversize_kms_wrap():
    h = _v3_header(kms_wrap=b"")
    blob = bytearray(h.pack())
    oversize = KMS_WRAP_MAX + 1
    blob[88:90] = oversize.to_bytes(2, "big")


    blob += b"\x00" * oversize
    with pytest.raises(HeaderParameterOutOfRange):
        Header.unpack(bytes(blob))

def test_v3_unpack_rejects_u16_max_kms_wrap():
    h = _v3_header(kms_wrap=b"")
    blob = bytearray(h.pack())
    blob[88:90] = (0xFFFF).to_bytes(2, "big")
    blob += b"\x00" * 0xFFFF
    with pytest.raises(HeaderParameterOutOfRange):
        Header.unpack(bytes(blob))

def test_v3_pack_rejects_bad_header_salt_size():
    h = _v3_header(header_salt=b"\x00" * (HEADER_SALT_LEN - 1))
    with pytest.raises(ValueError, match="header_salt"):
        h.pack()

def test_v3_pack_rejects_bad_yk_nonce_size():
    h = _v3_header(yk_nonce=b"\x00" * (YK_CHALLENGE_NONCE_LEN - 1))
    with pytest.raises(ValueError, match="yk_challenge_nonce"):
        h.pack()

def test_v3_pbkdf2_kdf_params_roundtrip():
    h = _v3_header(kdf_params=KdfParams.default_pbkdf2(), kms_wrap=b"wrap-me")
    parsed = Header.unpack(h.pack())
    assert parsed.kdf.kdf_id == KDF_PBKDF2
    assert parsed.kdf.iterations == h.kdf.iterations
    assert parsed.kms_wrap == b"wrap-me"

def test_v3_as_aad_includes_full_header():
    wrap = b"\xaa" * 64
    h = _v3_header(kms_wrap=wrap, inner_len=5000)
    aad = h.as_aad()

    assert len(aad) == HEADER_SIZE_V3_BASE + len(wrap)

    assert aad[:52] == h.pack()[:52]

    assert aad[52:56] == b"\x00\x00\x00\x00"

    assert aad[56:72] == h.header_salt
    assert aad[72:88] == h.yk_challenge_nonce

    assert aad[HEADER_SIZE_V3_BASE:] == wrap

def test_v3_and_v2_are_distinguishable_by_version():
    v2_blob = _argon_header().pack()
    v3_blob = _v3_header().pack()
    assert v2_blob[1] == VERSION_V2
    assert v3_blob[1] == VERSION_V3
    assert len(v2_blob) == HEADER_SIZE_V2
    assert len(v3_blob) == HEADER_SIZE_V3_BASE

def test_v3_unpack_ignores_trailing_bytes():
    h = _v3_header(kms_wrap=b"\xbb" * 32)
    tail = b"CIPHERTEXT_WOULD_GO_HERE"
    parsed = Header.unpack(h.pack() + tail)
    assert parsed.kms_wrap == b"\xbb" * 32
    assert parsed.packed_size == HEADER_SIZE_V3_BASE + 32

def test_v3_packed_size_matches_actual_length():
    for wrap_len in (0, 1, 100, 512):
        h = _v3_header(kms_wrap=b"\xcc" * wrap_len)
        assert h.packed_size == len(h.pack())
