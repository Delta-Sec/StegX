import os
import tempfile

import numpy as np
import pytest
from PIL import Image

from stegx.steganography import (
    EmbedOptions,
    bits_to_bytes,
    bytes_to_bits_iterator,
    calculate_lsb_capacity,
    embed_v2,
    extract_v2,
)

TEST_PASSWORD = "sufficiently-long-test-passphrase-42"

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as t:
        yield t

@pytest.fixture
def sample_data():
    return b"StegX v2 steganography test data 1234567890!@#$%^&*()"

@pytest.fixture
def create_test_image(temp_dir):
    def _create(width, height, mode="RGB", filename=None):
        filepath = os.path.join(temp_dir, filename or f"test_{mode}_{width}x{height}.png")
        rng = np.random.default_rng(seed=42)
        if mode == "RGB":
            arr = rng.integers(0, 256, (height, width, 3), dtype=np.uint8)
        elif mode == "RGBA":
            arr = rng.integers(0, 256, (height, width, 4), dtype=np.uint8)
        elif mode == "L":
            arr = rng.integers(0, 256, (height, width), dtype=np.uint8)
        elif mode == "P":
            img = Image.new("P", (width, height), color=0)
            for y in range(height):
                for x in range(width):
                    img.putpixel((x, y), (x + y) % 256)
            img.save(filepath)
            return filepath
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        Image.fromarray(arr, mode).save(filepath)
        return filepath

    return _create

def test_bytes_to_bits_iterator_roundtrip():
    for b in (b"", b"\x00", b"\xff", b"Hello", bytes(range(256))):
        bits = list(bytes_to_bits_iterator(b))
        assert bits_to_bytes(bits) == b

def test_calculate_lsb_capacity(create_test_image):
    rgb = create_test_image(100, 100, "RGB")
    with Image.open(rgb) as img:
        cap = calculate_lsb_capacity(img)
    assert cap > 0
    assert cap < 100 * 100 * 3

    gray = create_test_image(100, 100, "L")
    with Image.open(gray) as img:
        cap = calculate_lsb_capacity(img)
    assert cap > 0
    assert cap < 100 * 100

def test_calculate_capacity_rejects_unsupported_mode():
    with pytest.raises(ValueError):
        calculate_lsb_capacity(Image.new("CMYK", (50, 50)))

def test_embed_and_extract_rgb(create_test_image, sample_data, temp_dir):
    cover = create_test_image(200, 200, "RGB")
    stego = os.path.join(temp_dir, "stego_rgb.png")
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    assert os.path.exists(stego)
    assert extract_v2(stego, TEST_PASSWORD) == sample_data

def test_embed_and_extract_grayscale(create_test_image, sample_data, temp_dir):
    cover = create_test_image(300, 300, "L")
    stego = os.path.join(temp_dir, "stego_gray.png")
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    assert extract_v2(stego, TEST_PASSWORD) == sample_data

def test_wrong_password_rejected(create_test_image, sample_data, temp_dir):
    cover = create_test_image(200, 200, "RGB")
    stego = os.path.join(temp_dir, "stego.png")
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    with pytest.raises(ValueError):
        extract_v2(stego, "not-the-right-password")

def test_capacity_exceeded_raises(create_test_image, temp_dir):
    cover = create_test_image(10, 10, "L")
    stego = os.path.join(temp_dir, "stego_small.png")
    oversized = b"X" * 500
    with pytest.raises(ValueError):
        embed_v2(cover, oversized, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))

def test_max_fill_ratio_enforced(create_test_image, temp_dir):
    cover = create_test_image(80, 80, "RGB")
    stego = os.path.join(temp_dir, "stego.png")
    with pytest.raises(ValueError):
        embed_v2(cover, b"A" * 600, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=0.10))

def test_palette_image_gets_converted(create_test_image, sample_data, temp_dir):
    cover = create_test_image(100, 100, "P")
    stego = os.path.join(temp_dir, "stego_palette.png")
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    assert extract_v2(stego, TEST_PASSWORD) == sample_data
    with Image.open(stego) as img:
        assert img.mode != "P"

def test_file_not_found_errors():
    with pytest.raises(FileNotFoundError):
        embed_v2("missing.png", b"x", "out.png", TEST_PASSWORD, EmbedOptions())
    with pytest.raises(FileNotFoundError):
        extract_v2("missing.png", TEST_PASSWORD)

def test_empty_payload_roundtrip(create_test_image, temp_dir):
    cover = create_test_image(200, 200, "RGB")
    stego = os.path.join(temp_dir, "stego_empty.png")
    embed_v2(cover, b"", stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    assert extract_v2(stego, TEST_PASSWORD) == b""

def test_always_split_cover_with_phantom(create_test_image, sample_data, temp_dir):
    cover = create_test_image(400, 400, "RGB")
    stego = os.path.join(temp_dir, "stego_phantom.png")
    opts = EmbedOptions(always_split_cover=True, max_fill_ratio=1.0)
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, opts)

    assert extract_v2(stego, TEST_PASSWORD) == sample_data

    with pytest.raises(ValueError):
        extract_v2(stego, "wrong-password-xyz")

def test_hill_adaptive_mode_roundtrip(create_test_image, sample_data, temp_dir):
    cover = create_test_image(400, 400, "RGB")
    stego = os.path.join(temp_dir, "stego_hill.png")
    opts = EmbedOptions(
        use_adaptive=True,
        adaptive_cost_mode="hill",
        max_fill_ratio=1.0,
    )
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, opts)
    assert extract_v2(stego, TEST_PASSWORD) == sample_data

def test_dual_cipher_and_matrix_embedding(create_test_image, sample_data, temp_dir):
    cover = create_test_image(400, 400, "RGB")
    stego = os.path.join(temp_dir, "stego_hard.png")
    opts = EmbedOptions(
        dual_cipher=True,
        use_matrix_embedding=True,
        max_fill_ratio=1.0,
    )
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, opts)
    assert extract_v2(stego, TEST_PASSWORD) == sample_data

def test_keyfile_enforced(create_test_image, sample_data, temp_dir):
    cover = create_test_image(300, 300, "RGB")
    stego = os.path.join(temp_dir, "stego_kf.png")
    keyfile = b"\x00" * 32 + b"extra"
    opts = EmbedOptions(keyfile_bytes=keyfile, max_fill_ratio=1.0)
    embed_v2(cover, sample_data, stego, TEST_PASSWORD, opts)
    assert extract_v2(stego, TEST_PASSWORD, keyfile_bytes=keyfile) == sample_data
    with pytest.raises(ValueError):
        extract_v2(stego, TEST_PASSWORD)

def test_decoy_deniability(create_test_image, temp_dir):
    cover = create_test_image(500, 500, "RGB")
    stego = os.path.join(temp_dir, "stego_decoy.png")
    real_plaintext = b"the real secret"
    decoy_plaintext = b"a harmless cover story"
    opts = EmbedOptions(
        decoy_file_bytes=decoy_plaintext,
        decoy_filename="decoy.txt",
        decoy_password="decoy-passphrase-xyz-456",
        max_fill_ratio=1.0,
    )
    embed_v2(cover, real_plaintext, stego, TEST_PASSWORD, opts)
    assert extract_v2(stego, TEST_PASSWORD) == real_plaintext

    from stegx.utils import parse_payload

    decoy_blob = extract_v2(stego, "decoy-passphrase-xyz-456")
    assert decoy_blob != real_plaintext
    recovered_name, recovered_data = parse_payload(decoy_blob)
    assert recovered_name == "decoy.txt"
    assert recovered_data == decoy_plaintext

if __name__ == "__main__":
    pytest.main(["-v", __file__])
