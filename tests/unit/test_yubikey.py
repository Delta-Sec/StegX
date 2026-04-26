
import pytest
from cryptography.exceptions import InvalidTag

from stegx.crypto import EncryptOptions, decrypt_data, encrypt_data
from stegx.header import FLAG_YUBIKEY, Header
from stegx.kdf import KdfParams
from stegx.yubikey import (
    YUBIKEY_RESPONSE_LEN,
    MockYubiKey,
    YubiKeyError,
    resolve_yubikey_response,
)

def test_mock_yubikey_is_deterministic():
    yk = MockYubiKey(secret=b"shared-between-tests")
    challenge = b"\x11" * 32
    r1 = yk.challenge_response(challenge)
    r2 = yk.challenge_response(challenge)
    assert r1 == r2
    assert len(r1) == YUBIKEY_RESPONSE_LEN

def test_mock_yubikey_different_secrets_diverge():
    a = MockYubiKey(secret=b"secret-a")
    b = MockYubiKey(secret=b"secret-b")
    challenge = b"c" * 16
    assert a.challenge_response(challenge) != b.challenge_response(challenge)

def test_mock_yubikey_rejects_empty_challenge():
    yk = MockYubiKey()
    with pytest.raises(ValueError):
        yk.challenge_response(b"")

def test_mock_yubikey_rejects_empty_secret():
    with pytest.raises(ValueError):
        MockYubiKey(secret=b"")

def test_resolve_from_override():
    explicit = b"\xaa" * YUBIKEY_RESPONSE_LEN
    assert resolve_yubikey_response(b"c", response_override=explicit) == explicit

def test_resolve_rejects_wrong_length():
    with pytest.raises(YubiKeyError):
        resolve_yubikey_response(b"c", response_override=b"\x00" * 10)

def test_resolve_from_file_hex(tmp_path):
    resp = b"\xff" * YUBIKEY_RESPONSE_LEN
    p = tmp_path / "r.hex"
    p.write_text(resp.hex())
    got = resolve_yubikey_response(b"c", response_file=str(p))
    assert got == resp

def test_resolve_from_file_raw(tmp_path):
    resp = b"\x01" * YUBIKEY_RESPONSE_LEN
    p = tmp_path / "r.bin"
    p.write_bytes(resp)
    got = resolve_yubikey_response(b"c", response_file=str(p))
    assert got == resp

def test_resolve_via_backend():
    yk = MockYubiKey(secret=b"k")
    got = resolve_yubikey_response(b"challenge-bytes", backend=yk)
    assert len(got) == YUBIKEY_RESPONSE_LEN

def test_encrypt_decrypt_with_yubikey_roundtrip():
    yk = MockYubiKey(secret=b"shared")
    challenge = b"\x42" * 32
    response = yk.challenge_response(challenge)

    opts = EncryptOptions(
        kdf_params=KdfParams.default_argon2id(),
        yubikey_response=response,
    )
    ct = encrypt_data(b"hello hardware", "secure-passphrase-42", opts)

    header = Header.unpack(ct)
    assert header.has(FLAG_YUBIKEY)


    assert decrypt_data(ct, "secure-passphrase-42", yubikey_response=response) == b"hello hardware"


    with pytest.raises(ValueError, match="YubiKey"):
        decrypt_data(ct, "secure-passphrase-42")


    bad = bytes(b ^ 0xFF for b in response)
    with pytest.raises(InvalidTag):
        decrypt_data(ct, "secure-passphrase-42", yubikey_response=bad)
