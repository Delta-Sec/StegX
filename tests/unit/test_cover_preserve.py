from __future__ import annotations

import glob
import os

import pytest
from PIL import Image

from stegx.cover_preserve import (
    CoverEncoderParams,
    save_as_stego_png,
    sniff_png_encoder,
)

@pytest.fixture
def rgb_image():
    return Image.new("RGB", (32, 32), color=(128, 64, 255))

@pytest.fixture
def sentinel_original(tmp_path, rgb_image):
    dest = tmp_path / "stego.png"


    Image.new("RGB", (32, 32), color=(0, 0, 0)).save(dest, format="PNG")
    return dest

def test_save_atomic_happy_path(tmp_path, rgb_image):
    dest = tmp_path / "out.png"
    save_as_stego_png(rgb_image, str(dest), CoverEncoderParams())
    assert dest.is_file()

    with Image.open(dest) as reopened:
        reopened.load()
        assert reopened.size == rgb_image.size
        assert reopened.mode == rgb_image.mode

    tmps = glob.glob(str(tmp_path / ".stegx_save_*.tmp.png"))
    assert tmps == []

def test_save_preserves_original_on_pil_failure(
    tmp_path, rgb_image, sentinel_original, monkeypatch
):
    original_bytes = sentinel_original.read_bytes()


    real_save = Image.Image.save

    def exploding_save(self, fp, *args, **kwargs):
        raise OSError("simulated disk failure mid-write")

    monkeypatch.setattr(Image.Image, "save", exploding_save)

    with pytest.raises(OSError, match="simulated disk failure"):
        save_as_stego_png(
            rgb_image, str(sentinel_original), CoverEncoderParams()
        )


    monkeypatch.setattr(Image.Image, "save", real_save)


    assert sentinel_original.read_bytes() == original_bytes

    tmps = glob.glob(str(tmp_path / ".stegx_save_*.tmp.png"))
    assert tmps == []

def test_save_cleans_tempfile_on_replace_failure(
    tmp_path, rgb_image, monkeypatch
):
    dest = tmp_path / "out.png"


    import stegx.cover_preserve as _cp_mod

    def boom(src, dst):
        raise PermissionError("simulated AV hold")

    monkeypatch.setattr(_cp_mod.os, "replace", boom)

    with pytest.raises(PermissionError):
        save_as_stego_png(rgb_image, str(dest), CoverEncoderParams())


    assert not dest.exists()

    tmps = glob.glob(str(tmp_path / ".stegx_save_*.tmp.png"))
    assert tmps == []

def test_save_uses_same_directory_for_tempfile(tmp_path, rgb_image, monkeypatch):
    dest = tmp_path / "out.png"
    seen_dirs: list = []

    real_mkstemp = __import__("tempfile").mkstemp

    def spy_mkstemp(*args, **kwargs):
        seen_dirs.append(kwargs.get("dir"))
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(
        "stegx.cover_preserve.tempfile.mkstemp", spy_mkstemp
    )

    save_as_stego_png(rgb_image, str(dest), CoverEncoderParams())

    assert seen_dirs, "tempfile.mkstemp was not called"
    assert os.path.abspath(seen_dirs[0]) == os.path.abspath(str(tmp_path))

def test_sniff_png_encoder_on_our_own_output(tmp_path, rgb_image):
    dest = tmp_path / "sniff.png"
    params = CoverEncoderParams(compress_level=9)
    save_as_stego_png(rgb_image, str(dest), params, preserve=True)
    sniffed = sniff_png_encoder(str(dest))


    assert sniffed.compress_level == 9
