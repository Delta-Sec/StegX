import os
import tempfile

import numpy as np
import pytest
from PIL import Image
from cryptography.exceptions import InvalidTag

from stegx.crypto import EncryptOptions, decrypt_data, encrypt_data
from stegx.header import HEADER_SIZE, Header
from stegx.kdf import KdfParams
from stegx.sentinel import cover_fingerprint, derive_sentinel
from stegx.steganography import EmbedOptions, embed_v2, extract_v2

TEST_PASSWORD = "security-test-passphrase-ZYX-987"

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as t:
        yield t

@pytest.fixture
def cover(temp_dir):
    def _make(size=300):
        rng = np.random.default_rng(seed=7)
        arr = rng.integers(0, 256, (size, size, 3), dtype=np.uint8)
        p = os.path.join(temp_dir, f"cover_{size}.png")
        Image.fromarray(arr, "RGB").save(p)
        return p

    return _make

@pytest.mark.security
def test_aad_tamper_is_detected():
    payload = b"sensitive"
    opts = EncryptOptions(kdf_params=KdfParams.default_argon2id())
    stream = bytearray(encrypt_data(payload, TEST_PASSWORD, opts))

    stream[3] ^= 0x80
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_data(bytes(stream), TEST_PASSWORD)

@pytest.mark.security
def test_sentinel_is_image_bound():
    key = b"\x42" * 32
    img_a = Image.new("RGB", (100, 100))
    img_b = Image.new("RGB", (101, 100))
    sent_a = derive_sentinel(key, cover_fingerprint(img_a))
    sent_b = derive_sentinel(key, cover_fingerprint(img_b))
    assert sent_a != sent_b

@pytest.mark.security
def test_wrong_password_rejected(temp_dir, cover):
    stego = os.path.join(temp_dir, "s.png")
    embed_v2(cover(), b"payload", stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    with pytest.raises(ValueError):
        extract_v2(stego, "not-the-password")

@pytest.mark.security
def test_stego_changes_are_low_rate(temp_dir, cover):
    cover_path = cover(300)
    stego_path = os.path.join(temp_dir, "stego.png")
    payload = b"short"
    embed_v2(cover_path, payload, stego_path, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))

    cover_arr = np.array(Image.open(cover_path))
    stego_arr = np.array(Image.open(stego_path))
    diff = np.abs(cover_arr.astype(int) - stego_arr.astype(int))

    assert diff.max() <= 1

    changed = (diff != 0).sum()
    total = cover_arr.size
    assert changed / total < 0.15

@pytest.mark.security
def test_output_has_no_pillow_software_chunk(temp_dir, cover):
    stego = os.path.join(temp_dir, "out.png")
    embed_v2(cover(), b"p", stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    with open(stego, "rb") as f:
        blob = f.read()
    assert b"Software" not in blob
    assert b"Pillow" not in blob

@pytest.mark.security
def test_header_layout_stable():
    hdr = Header(
        kdf=KdfParams.default_argon2id(),
        flags=0,
        salt=b"\x00" * 16,
        aes_nonce=b"\x00" * 12,
        chacha_nonce=b"\x00" * 12,
        inner_ct_length=0,
    )
    assert len(hdr.pack()) == HEADER_SIZE == 56
