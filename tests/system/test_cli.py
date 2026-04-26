import os
import subprocess
import sys
import tempfile

import numpy as np
import pytest
from PIL import Image

TEST_PASSWORD = "cli-system-test-passphrase-77"
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


SRC_DIR = os.path.join(PROJECT_ROOT, "src")

def _run(args, stdin_text=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "stegx", *args],
        input=stdin_text,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as t:
        yield t

@pytest.fixture
def sample_payload(temp_dir):
    p = os.path.join(temp_dir, "payload.bin")
    with open(p, "wb") as f:
        f.write(b"CLI system-test payload \x00\x01\x02\x03" * 4)
    return p

@pytest.fixture
def cover_image(temp_dir):
    rng = np.random.default_rng(seed=11)
    arr = rng.integers(0, 256, (200, 200, 3), dtype=np.uint8)
    p = os.path.join(temp_dir, "cover.png")
    Image.fromarray(arr, "RGB").save(p)
    return p

def test_help_runs():
    r = _run(["--help"])
    assert r.returncode == 0
    assert "StegX" in r.stdout

def test_version_runs():
    r = _run(["--version"])
    assert r.returncode == 0

def test_encode_decode_with_stdin_password(temp_dir, cover_image, sample_payload):
    stego = os.path.join(temp_dir, "stego.png")
    r_enc = _run(
        [
            "encode",
            "-i", cover_image,
            "-f", sample_payload,
            "-o", stego,
            "--password-stdin",
        ],
        stdin_text=TEST_PASSWORD + "\n",
    )
    assert r_enc.returncode == 0, r_enc.stderr
    assert os.path.isfile(stego)

    out_dir = os.path.join(temp_dir, "extracted")
    r_dec = _run(
        [
            "decode",
            "-i", stego,
            "-d", out_dir,
            "--password-stdin",
        ],
        stdin_text=TEST_PASSWORD + "\n",
    )
    assert r_dec.returncode == 0, r_dec.stderr
    with open(os.path.join(out_dir, os.path.basename(sample_payload)), "rb") as f:
        with open(sample_payload, "rb") as orig:
            assert f.read() == orig.read()

def test_wrong_password_exit_code(temp_dir, cover_image, sample_payload):
    stego = os.path.join(temp_dir, "stego.png")
    _run(
        ["encode", "-i", cover_image, "-f", sample_payload, "-o", stego, "--password-stdin"],
        stdin_text=TEST_PASSWORD + "\n",
    )
    out_dir = os.path.join(temp_dir, "out")
    r = _run(
        ["decode", "-i", stego, "-d", out_dir, "--password-stdin"],
        stdin_text="wrong-password\n",
    )
    assert r.returncode != 0

def test_missing_subcommand_shows_error():
    r = _run([])
    assert r.returncode != 0

def test_benchmark_subcommand_runs():
    r = _run(["benchmark", "--iterations", "1", "--size-kib", "4"])
    assert r.returncode == 0, r.stderr
    assert "Argon2id KDF timing" in r.stdout
    assert "Compression multiplexer" in r.stdout

def test_version_shows_extras_status():
    r = _run(["--version"])
    assert r.returncode == 0
    assert "stegx" in r.stdout
    assert "argon2-cffi" in r.stdout
    assert "ykman (YubiKey)" in r.stdout

def test_benchmark_calibrate_runs():
    r = _run(["benchmark", "--calibrate", "--target-ms", "200"])
    assert r.returncode == 0, r.stderr
    assert "Recommended Argon2id params" in r.stdout


import shutil

_STEGX_BIN = shutil.which("stegx")

@pytest.mark.skipif(_STEGX_BIN is None, reason="`stegx` console script not on PATH")
def test_installed_binary_version():
    r = subprocess.run(
        [_STEGX_BIN, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "stegx" in r.stdout

@pytest.mark.skipif(_STEGX_BIN is None, reason="`stegx` console script not on PATH")
def test_installed_binary_roundtrip(temp_dir, cover_image, sample_payload):
    stego = os.path.join(temp_dir, "installed_stego.png")
    out_dir = os.path.join(temp_dir, "installed_out")

    r_enc = subprocess.run(
        [_STEGX_BIN, "encode",
         "-i", cover_image, "-f", sample_payload, "-o", stego,
         "--password-stdin"],
        input=TEST_PASSWORD + "\n",
        capture_output=True, text=True, timeout=180,
    )
    assert r_enc.returncode == 0, r_enc.stderr
    assert os.path.isfile(stego)

    r_dec = subprocess.run(
        [_STEGX_BIN, "decode", "-i", stego, "-d", out_dir, "--password-stdin"],
        input=TEST_PASSWORD + "\n",
        capture_output=True, text=True, timeout=180,
    )
    assert r_dec.returncode == 0, r_dec.stderr
    with open(os.path.join(out_dir, os.path.basename(sample_payload)), "rb") as f:
        with open(sample_payload, "rb") as orig:
            assert f.read() == orig.read()
