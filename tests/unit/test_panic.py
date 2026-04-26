
import os
import tempfile

import numpy as np
import pytest
from PIL import Image

from stegx.panic import (
    PANIC_MODE_DECOY,
    PANIC_MODE_SILENT,
    destroy_real_region_in_place,
)
from stegx.steganography import (
    EmbedOptions,
    embed_v2,
    extract_v2,
    extract_v2_with_region,
)
from stegx.utils import META_PANIC, META_PANIC_MODE, parse_payload_full

REAL_PASSWORD = "real-password-very-strong-xyz"
PANIC_PASSWORD = "panic-password-totally-different"

@pytest.fixture
def cover_path(tmp_path):
    rng = np.random.default_rng(seed=7)
    arr = rng.integers(0, 256, (400, 400, 3), dtype=np.uint8)
    p = tmp_path / "cover.png"
    Image.fromarray(arr, "RGB").save(p)
    return str(p)

def _embed_with_panic(cover_path, tmp_path, real_payload, panic_decoy=None):
    stego = str(tmp_path / "stego_panic.png")
    opts = EmbedOptions(
        max_fill_ratio=1.0,
        panic_password=PANIC_PASSWORD,
        panic_marker_payload=panic_decoy,
    )
    embed_v2(cover_path, real_payload, stego, REAL_PASSWORD, opts)
    return stego

def test_real_password_recovers_real_payload(cover_path, tmp_path):
    real = b"classified intelligence report"
    stego = _embed_with_panic(cover_path, tmp_path, real)
    assert extract_v2(stego, REAL_PASSWORD) == real

def test_panic_password_marks_payload_with_panic_flag(cover_path, tmp_path):
    stego = _embed_with_panic(cover_path, tmp_path, b"the real secret")
    decrypted, region = extract_v2_with_region(stego, PANIC_PASSWORD)
    _name, _data, meta = parse_payload_full(decrypted)
    assert meta.get(META_PANIC) is True
    assert meta.get(META_PANIC_MODE) == PANIC_MODE_SILENT
    assert region == "decoy-half"

def test_panic_mode_decoy_when_decoy_bytes_supplied(cover_path, tmp_path):
    stego = _embed_with_panic(
        cover_path, tmp_path,
        real_payload=b"real secret",
        panic_decoy=b"harmless cover story content",
    )
    decrypted, _region = extract_v2_with_region(stego, PANIC_PASSWORD)
    name, data, meta = parse_payload_full(decrypted)
    assert meta.get(META_PANIC) is True
    assert meta.get(META_PANIC_MODE) == PANIC_MODE_DECOY
    assert b"harmless cover story content" in data

def test_destruction_rewrites_real_region_lsbs(cover_path, tmp_path):
    real = b"super-sensitive data that must be destroyed"
    stego = _embed_with_panic(cover_path, tmp_path, real)

    assert extract_v2(stego, REAL_PASSWORD) == real


    _decrypted, region = extract_v2_with_region(stego, PANIC_PASSWORD)
    ok = destroy_real_region_in_place(stego, region)
    assert ok is True


    with pytest.raises(ValueError):
        extract_v2(stego, REAL_PASSWORD)


    panic_again, _ = extract_v2_with_region(stego, PANIC_PASSWORD)
    _name, _data, meta = parse_payload_full(panic_again)
    assert meta.get(META_PANIC) is True

def test_destruction_refuses_unknown_region(tmp_path, cover_path):
    stego = _embed_with_panic(cover_path, tmp_path, b"data")
    assert destroy_real_region_in_place(stego, "real-full") is False

def test_destruction_is_noop_on_missing_file(tmp_path):
    assert destroy_real_region_in_place(str(tmp_path / "does-not-exist.png"),
                                        "decoy-half") is False
