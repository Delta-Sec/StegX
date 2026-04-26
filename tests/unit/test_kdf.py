
import pytest

from stegx.kdf import (
    HKDF_INFO_AES,
    HKDF_INFO_CHACHA,
    HKDF_INFO_SEED,
    HKDF_INFO_SENTINEL,
    KDF_ARGON2ID,
    KDF_PBKDF2,
    KdfParams,
    derive_legacy_seed_from_password,
    derive_master_key,
    hkdf_subkey,
    seed_int_from_subkey,
)

def test_argon2id_master_key_is_deterministic():
    params = KdfParams(kdf_id=KDF_ARGON2ID, time_cost=1, memory_cost_kib=8192, parallelism=1)
    salt = b"\x00" * 16
    a = derive_master_key("pw", salt, params)
    b = derive_master_key("pw", salt, params)
    assert a == b == bytes(a)
    assert len(a) == 32

def test_different_password_yields_different_key():
    params = KdfParams(kdf_id=KDF_ARGON2ID, time_cost=1, memory_cost_kib=8192, parallelism=1)
    salt = b"\x11" * 16
    assert derive_master_key("pw", salt, params) != derive_master_key("pw2", salt, params)

def test_keyfile_changes_key():
    params = KdfParams(kdf_id=KDF_ARGON2ID, time_cost=1, memory_cost_kib=8192, parallelism=1)
    salt = b"\x22" * 16
    without = derive_master_key("pw", salt, params)
    with_kf = derive_master_key("pw", salt, params, keyfile_bytes=b"extra")
    assert without != with_kf

def test_pbkdf2_master_key():
    params = KdfParams(kdf_id=KDF_PBKDF2, iterations=1000)
    salt = b"\x33" * 16
    assert derive_master_key("pw", salt, params) == derive_master_key("pw", salt, params)

def test_hkdf_domain_separation():
    master = b"\x42" * 32
    aes = hkdf_subkey(master, HKDF_INFO_AES)
    cha = hkdf_subkey(master, HKDF_INFO_CHACHA)
    seed = hkdf_subkey(master, HKDF_INFO_SEED, length=8)
    sent = hkdf_subkey(master, HKDF_INFO_SENTINEL)
    values = [aes, cha, seed, sent]
    assert len({v for v in values}) == len(values)

def test_seed_int_is_non_negative():
    subkey = bytes(range(8))
    assert seed_int_from_subkey(subkey) >= 0

def test_legacy_seed_matches_known_derivation():
    seed = derive_legacy_seed_from_password("hello")
    assert isinstance(seed, int)
    assert seed == derive_legacy_seed_from_password("hello")
    assert seed != derive_legacy_seed_from_password("Hello")

def test_empty_password_rejected():
    params = KdfParams.default_argon2id()
    with pytest.raises(ValueError):
        derive_master_key("", b"\x00" * 16, params)


_FAST_PARAMS = KdfParams(kdf_id=KDF_ARGON2ID, time_cost=1, memory_cost_kib=8192, parallelism=1)

def test_factor_framing_defeats_cross_factor_collision():
    salt = b"\x77" * 16
    a = derive_master_key("ab", salt, _FAST_PARAMS, keyfile_bytes=b"c")
    b = derive_master_key("a", salt, _FAST_PARAMS, keyfile_bytes=b"bc")
    assert a != b

def test_yubikey_factor_is_separately_framed():
    salt = b"\x88" * 16
    a = derive_master_key(
        "pw", salt, _FAST_PARAMS, keyfile_bytes=b"hello", yubikey_response=None
    )
    b = derive_master_key(
        "pw", salt, _FAST_PARAMS, keyfile_bytes=None, yubikey_response=b"hello"
    )
    assert a != b

def test_empty_vs_none_factor_are_equivalent():
    salt = b"\x99" * 16
    a = derive_master_key("pw", salt, _FAST_PARAMS, keyfile_bytes=None)
    b = derive_master_key("pw", salt, _FAST_PARAMS, keyfile_bytes=b"")
    assert a == b

def test_header_salt_changes_master_key():
    salt = b"\xaa" * 16
    base = derive_master_key("pw", salt, _FAST_PARAMS)
    with_hs = derive_master_key(
        "pw", salt, _FAST_PARAMS, header_salt=b"\x01" * 16
    )
    other_hs = derive_master_key(
        "pw", salt, _FAST_PARAMS, header_salt=b"\x02" * 16
    )

    assert base != with_hs
    assert with_hs != other_hs
    assert len(with_hs) == 32

def test_header_salt_is_deterministic_per_value():
    salt = b"\xbb" * 16
    hs = b"\xcc" * 16
    a = derive_master_key("pw", salt, _FAST_PARAMS, header_salt=hs)
    b = derive_master_key("pw", salt, _FAST_PARAMS, header_salt=hs)
    assert a == b

def test_hkdf_extract_matches_rfc5869():
    import hmac
    import hashlib
    from stegx.kdf import hkdf_extract

    salt = b"\x00" * 16
    ikm = b"input keying material"
    expected = hmac.new(salt, ikm, hashlib.sha256).digest()
    assert hkdf_extract(salt, ikm) == expected
