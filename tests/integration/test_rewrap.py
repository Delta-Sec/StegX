
import argparse
import os
import tempfile

import numpy as np
import pytest
from PIL import Image

from stegx import perform_encode, perform_rewrap
from stegx.steganography import extract_v2
from tests._test_credentials import derive_password


OLD_PASSWORD = derive_password("rewrap-old")
NEW_PASSWORD = derive_password("rewrap-new")

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d

@pytest.fixture
def cover_image(temp_dir):
    rng = np.random.default_rng(seed=11)
    arr = rng.integers(0, 256, (300, 300, 3), dtype=np.uint8)
    p = os.path.join(temp_dir, "cover.png")
    Image.fromarray(arr, "RGB").save(p)
    return p

@pytest.fixture
def payload_file(temp_dir):
    p = os.path.join(temp_dir, "secret.bin")
    with open(p, "wb") as f:
        f.write(b"rotation-target data 0123456789" * 10)
    return p

def _enc_args(image, infile, output, password):
    return argparse.Namespace(
        image=image, file=infile, output=output,
        password=password, password_stdin=False, keyfile=None,
        kdf="argon2id", dual_cipher=False, adaptive=False,
        adaptive_cutoff=0.40, adaptive_mode="laplacian",
        matrix_embedding=False, max_fill=100.0, strict_password=False,
        no_preserve_cover=False, compress=True, compression="best",
        always_split_cover=False, fips=False,
        decoy_file=None, decoy_password=None,
        panic_password=None, panic_decoy=None,
        polyglot_zip=None, yubikey=False, yubikey_response_file=None,
        audit_log=None,
    )

def _rewrap_args(image, output=None):
    return argparse.Namespace(
        image=image, output=output,
        old_keyfile=None, keyfile=None,
        old_yubikey=False, old_yubikey_response_file=None,
        yubikey=False, yubikey_response_file=None,
        kdf="argon2id", dual_cipher=False, adaptive=False,
        adaptive_cutoff=0.40, adaptive_mode="laplacian",
        matrix_embedding=False, max_fill=100.0, strict_password=False,
        no_preserve_cover=False, compress=True, compression="best",
        always_split_cover=False, fips=False,
        audit_log=None,
    )

@pytest.fixture
def stego_image(temp_dir, cover_image, payload_file, monkeypatch):
    stego = os.path.join(temp_dir, "stego.png")
    enc_args = _enc_args(cover_image, payload_file, stego, OLD_PASSWORD)
    assert perform_encode(enc_args) is True
    return stego

def test_rewrap_changes_password(stego_image, monkeypatch):

    answers = iter([OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("stegx.getpass.getpass", lambda *a, **k: next(answers))

    args = _rewrap_args(stego_image)
    assert perform_rewrap(args) is True


    with pytest.raises(ValueError):
        extract_v2(stego_image, OLD_PASSWORD)


    recovered = extract_v2(stego_image, NEW_PASSWORD)
    assert recovered

def test_rewrap_to_separate_output(stego_image, temp_dir, monkeypatch):
    new_path = os.path.join(temp_dir, "stego_rotated.png")
    answers = iter([OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("stegx.getpass.getpass", lambda *a, **k: next(answers))

    args = _rewrap_args(stego_image, output=new_path)
    assert perform_rewrap(args) is True


    assert extract_v2(stego_image, OLD_PASSWORD)
    assert extract_v2(new_path, NEW_PASSWORD)

def test_rewrap_rejects_same_passwords(stego_image, monkeypatch):
    answers = iter([OLD_PASSWORD, OLD_PASSWORD, OLD_PASSWORD])
    monkeypatch.setattr("stegx.getpass.getpass", lambda *a, **k: next(answers))

    args = _rewrap_args(stego_image)
    assert perform_rewrap(args) is False

def test_rewrap_rejects_bad_old_password(stego_image, monkeypatch):
    answers = iter(["wrong-old-password-xyz", NEW_PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("stegx.getpass.getpass", lambda *a, **k: next(answers))

    args = _rewrap_args(stego_image)
    assert perform_rewrap(args) is False


def _split_cover_stego(temp_dir, cover_image, payload_file):
    stego = os.path.join(temp_dir, "stego_split.png")
    args = _enc_args(cover_image, payload_file, stego, OLD_PASSWORD)
    args.always_split_cover = True
    assert perform_encode(args) is True
    return stego

def _panic_stego(temp_dir, cover_image, payload_file):
    stego = os.path.join(temp_dir, "stego_panic.png")
    args = _enc_args(cover_image, payload_file, stego, OLD_PASSWORD)
    args.panic_password = "panic-passphrase-totally-different-from-old-42"
    assert perform_encode(args) is True
    return stego

def test_rewrap_preserves_split_cover_layout(
    temp_dir, cover_image, payload_file, monkeypatch
):
    stego = _split_cover_stego(temp_dir, cover_image, payload_file)
    answers = iter([OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("stegx.getpass.getpass", lambda *a, **k: next(answers))

    args = _rewrap_args(stego)
    args.always_split_cover = True
    assert perform_rewrap(args) is True


    with pytest.raises(Exception):
        extract_v2(stego, OLD_PASSWORD)
    assert extract_v2(stego, NEW_PASSWORD)

def test_rewrap_over_panic_stego(
    temp_dir, cover_image, payload_file, monkeypatch
):
    stego = _panic_stego(temp_dir, cover_image, payload_file)
    answers = iter([OLD_PASSWORD, NEW_PASSWORD, NEW_PASSWORD])
    monkeypatch.setattr("stegx.getpass.getpass", lambda *a, **k: next(answers))

    args = _rewrap_args(stego)
    assert perform_rewrap(args) is True


    assert extract_v2(stego, NEW_PASSWORD)

def test_fips_rejects_yubikey_combination(
    temp_dir, cover_image, payload_file, monkeypatch
):
    monkeypatch.setattr("stegx.fips.assert_fips_runtime", lambda: None)

    yk_response_path = os.path.join(temp_dir, "yk-response.bin")
    with open(yk_response_path, "wb") as f:
        f.write(b"\xaa" * 20)

    stego = os.path.join(temp_dir, "stego_yk_fips.png")
    enc = _enc_args(cover_image, payload_file, stego, OLD_PASSWORD)
    enc.yubikey = True
    enc.yubikey_response_file = yk_response_path
    enc.fips = True

    assert perform_encode(enc) is False
    assert not os.path.exists(stego)
