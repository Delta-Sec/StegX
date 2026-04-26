
import argparse
import os
import tempfile

import numpy as np
import pytest
from PIL import Image

from stegx import perform_decode, perform_encode
from stegx.steganography import EmbedOptions, embed_v2, extract_v2

TEST_PASSWORD = "integration-test-passphrase-4242"

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as t:
        yield t

@pytest.fixture
def sample_data():
    return b"StegX integration test data 1234567890!@#$%^&*()"

@pytest.fixture
def test_file(temp_dir, sample_data):
    p = os.path.join(temp_dir, "payload.txt")
    with open(p, "wb") as f:
        f.write(sample_data)
    return p

@pytest.fixture
def test_image(temp_dir):
    rng = np.random.default_rng(seed=42)
    arr = rng.integers(0, 256, (200, 200, 3), dtype=np.uint8)
    img = Image.fromarray(arr, "RGB")
    p = os.path.join(temp_dir, "cover.png")
    img.save(p)
    return p

def _encode_args(image, infile, output):
    return argparse.Namespace(
        image=image,
        file=infile,
        output=output,
        password=TEST_PASSWORD,
        password_stdin=False,
        keyfile=None,
        kdf="argon2id",
        dual_cipher=False,
        adaptive=False,
        adaptive_cutoff=0.40,
        adaptive_mode="laplacian",
        matrix_embedding=False,
        max_fill=100.0,
        strict_password=False,
        no_preserve_cover=False,
        compress=True,
        compression="best",
        always_split_cover=False,
        fips=False,
        decoy_file=None,
        decoy_password=None,
    )

def _decode_args(image, destination):
    return argparse.Namespace(
        image=image,
        destination=destination,
        password=TEST_PASSWORD,
        password_stdin=False,
        keyfile=None,
    )

def test_full_encode_decode_flow(temp_dir, test_image, test_file, sample_data):
    stego = os.path.join(temp_dir, "stego.png")
    assert perform_encode(_encode_args(test_image, test_file, stego)) is True
    assert os.path.isfile(stego)

    out_dir = os.path.join(temp_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    assert perform_decode(_decode_args(stego, out_dir)) is True

    recovered = os.path.join(out_dir, os.path.basename(test_file))
    assert os.path.isfile(recovered)
    with open(recovered, "rb") as f:
        assert f.read() == sample_data

def test_core_embed_extract_bytes(temp_dir, test_image):
    stego = os.path.join(temp_dir, "stego_core.png")
    payload = b"raw v2 bytes payload"
    embed_v2(test_image, payload, stego, TEST_PASSWORD, EmbedOptions(max_fill_ratio=1.0))
    assert extract_v2(stego, TEST_PASSWORD) == payload

def test_wrong_password_decode_returns_false(temp_dir, test_image, test_file):
    stego = os.path.join(temp_dir, "stego.png")
    assert perform_encode(_encode_args(test_image, test_file, stego)) is True
    args = _decode_args(stego, os.path.join(temp_dir, "out"))
    args.password = "wrong-password"
    assert perform_decode(args) is False

def test_missing_cover_fails(temp_dir, test_file):
    stego = os.path.join(temp_dir, "stego.png")
    args = _encode_args("does-not-exist.png", test_file, stego)
    assert perform_encode(args) is False

def test_decode_to_stdout(temp_dir, test_image, test_file, sample_data, capsysbinary):
    stego = os.path.join(temp_dir, "stego.png")
    assert perform_encode(_encode_args(test_image, test_file, stego)) is True
    capsysbinary.readouterr()

    args = argparse.Namespace(
        image=stego,
        destination=None,
        stdout=True,
        password=TEST_PASSWORD,
        password_stdin=False,
        keyfile=None,
    )
    assert perform_decode(args) is True
    captured = capsysbinary.readouterr()
    assert captured.out == sample_data

def test_decode_dash_destination_means_stdout(temp_dir, test_image, test_file, sample_data, capsysbinary):
    stego = os.path.join(temp_dir, "stego.png")
    assert perform_encode(_encode_args(test_image, test_file, stego)) is True
    capsysbinary.readouterr()

    args = argparse.Namespace(
        image=stego,
        destination="-",
        stdout=False,
        password=TEST_PASSWORD,
        password_stdin=False,
        keyfile=None,
    )
    assert perform_decode(args) is True
    captured = capsysbinary.readouterr()
    assert captured.out == sample_data

def test_decode_requires_destination_or_stdout(temp_dir, test_image, test_file):
    stego = os.path.join(temp_dir, "stego.png")
    assert perform_encode(_encode_args(test_image, test_file, stego)) is True

    args = argparse.Namespace(
        image=stego,
        destination=None,
        stdout=False,
        password=TEST_PASSWORD,
        password_stdin=False,
        keyfile=None,
    )
    assert perform_decode(args) is False

def test_batch_multifile_roundtrip(temp_dir, test_image):
    f1 = os.path.join(temp_dir, "a.txt")
    f2 = os.path.join(temp_dir, "b.bin")
    f3 = os.path.join(temp_dir, "c.json")
    with open(f1, "wb") as f: f.write(b"contents of a")
    with open(f2, "wb") as f: f.write(b"\x00\x01\x02 binary contents of b \xff")
    with open(f3, "wb") as f: f.write(b'{"key": "value", "num": 42}')

    stego = os.path.join(temp_dir, "stego_bundle.png")
    enc = _encode_args(test_image, f1, stego)
    enc.file = [f1, f2, f3]
    assert perform_encode(enc) is True

    out_dir = os.path.join(temp_dir, "extracted_bundle")
    os.makedirs(out_dir, exist_ok=True)
    assert perform_decode(_decode_args(stego, out_dir)) is True

    for orig in (f1, f2, f3):
        recovered = os.path.join(out_dir, os.path.basename(orig))
        assert os.path.isfile(recovered), f"Missing bundle member: {recovered}"
        with open(orig, "rb") as a, open(recovered, "rb") as b:
            assert a.read() == b.read()
