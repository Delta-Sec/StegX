
import pytest
from cryptography.exceptions import InvalidTag

from stegx.crypto import (
    EncryptOptions,
    decrypt_data,
    decrypt_legacy_v1,
    encrypt_data,
)
from stegx.header import FLAG_DUAL_CIPHER, FLAG_KEYFILE, Header
from stegx.kdf import KdfParams

@pytest.fixture
def sample_data():
    return b"StegX v2 test data for encryption/decryption 1234567890!@#$%^&*()"

@pytest.fixture
def sample_password():
    return "StegXTestPassword123!@#"

@pytest.fixture
def default_options():
    return EncryptOptions(kdf_params=KdfParams.default_argon2id())

def test_encrypt_emits_valid_header(sample_data, sample_password, default_options):
    stream = encrypt_data(sample_data, sample_password, default_options)
    header = Header.unpack(stream)
    assert len(stream) > header.packed_size
    assert header.kdf.kdf_id == default_options.kdf_params.kdf_id
    assert header.inner_ct_length == len(stream) - header.packed_size

def test_roundtrip_argon2id(sample_data, sample_password, default_options):
    stream = encrypt_data(sample_data, sample_password, default_options)
    assert decrypt_data(stream, sample_password) == sample_data

def test_roundtrip_pbkdf2(sample_data, sample_password):
    opts = EncryptOptions(kdf_params=KdfParams(kdf_id=0x01, iterations=100_000))
    stream = encrypt_data(sample_data, sample_password, opts)
    assert decrypt_data(stream, sample_password) == sample_data

def test_wrong_password_fails(sample_data, sample_password, default_options):
    stream = encrypt_data(sample_data, sample_password, default_options)
    with pytest.raises(InvalidTag):
        decrypt_data(stream, sample_password + "x")

def test_corrupted_ciphertext_fails(sample_data, sample_password, default_options):
    stream = bytearray(encrypt_data(sample_data, sample_password, default_options))
    header = Header.unpack(bytes(stream))
    stream[header.packed_size] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_data(bytes(stream), sample_password)

def test_corrupted_header_aad_fails(sample_data, sample_password, default_options):
    stream = bytearray(encrypt_data(sample_data, sample_password, default_options))
    stream[3] ^= 0x80
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_data(bytes(stream), sample_password)

def test_dual_cipher_roundtrip(sample_data, sample_password):
    opts = EncryptOptions(kdf_params=KdfParams.default_argon2id(), dual_cipher=True)
    stream = encrypt_data(sample_data, sample_password, opts)
    header = Header.unpack(stream)
    assert header.has(FLAG_DUAL_CIPHER)
    assert decrypt_data(stream, sample_password) == sample_data

def test_keyfile_roundtrip(sample_data, sample_password):
    keyfile = b"\x00" * 32 + b"important-bytes"
    opts = EncryptOptions(kdf_params=KdfParams.default_argon2id(), keyfile_bytes=keyfile)
    stream = encrypt_data(sample_data, sample_password, opts)
    header = Header.unpack(stream)
    assert header.has(FLAG_KEYFILE)
    assert decrypt_data(stream, sample_password, keyfile_bytes=keyfile) == sample_data

def test_keyfile_required_for_decrypt(sample_data, sample_password):
    keyfile = b"bar" * 16
    opts = EncryptOptions(kdf_params=KdfParams.default_argon2id(), keyfile_bytes=keyfile)
    stream = encrypt_data(sample_data, sample_password, opts)
    with pytest.raises(ValueError):
        decrypt_data(stream, sample_password, keyfile_bytes=None)

def test_keyfile_wrong_bytes_fails(sample_data, sample_password):
    keyfile_a = b"\x01" * 32
    keyfile_b = b"\x02" * 32
    opts = EncryptOptions(kdf_params=KdfParams.default_argon2id(), keyfile_bytes=keyfile_a)
    stream = encrypt_data(sample_data, sample_password, opts)
    with pytest.raises(InvalidTag):
        decrypt_data(stream, sample_password, keyfile_bytes=keyfile_b)

def test_legacy_v1_roundtrip():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from stegx.crypto import (
        LEGACY_KEY_SIZE,
        LEGACY_NONCE_SIZE,
        LEGACY_PBKDF2_ITERATIONS,
        LEGACY_SALT_SIZE,
        _legacy_derive_key,
    )
    import os

    from tests._test_credentials import derive_password

    password = derive_password("legacy-v1")
    plaintext = b"old v1 payload"
    salt = os.urandom(LEGACY_SALT_SIZE)
    nonce = os.urandom(LEGACY_NONCE_SIZE)
    key = _legacy_derive_key(password, salt)
    assert len(key) == LEGACY_KEY_SIZE
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    legacy_blob = salt + nonce + ct

    assert decrypt_legacy_v1(legacy_blob, password) == plaintext
    with pytest.raises(InvalidTag):
        decrypt_legacy_v1(legacy_blob, password + "x")

    assert LEGACY_PBKDF2_ITERATIONS == 390_000

def test_empty_plaintext_roundtrip(sample_password, default_options):
    stream = encrypt_data(b"", sample_password, default_options)
    assert decrypt_data(stream, sample_password) == b""

@pytest.mark.parametrize(
    "plaintext",
    [b"a", b"StegX" * 1000, bytes(range(256)) * 2],
)
def test_parametrized_roundtrip(plaintext, sample_password, default_options):
    stream = encrypt_data(plaintext, sample_password, default_options)
    assert decrypt_data(stream, sample_password) == plaintext

def test_encrypt_rejects_non_bytes(sample_password, default_options):
    with pytest.raises(TypeError):
        encrypt_data("not bytes", sample_password, default_options)

def test_encrypt_rejects_empty_password(sample_data, default_options):
    with pytest.raises(ValueError):
        encrypt_data(sample_data, "", default_options)

if __name__ == "__main__":
    pytest.main(["-v", __file__])
