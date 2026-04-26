
import zipfile

import pytest
from PIL import Image

from stegx.polyglot import (
    _find_png_end,
    build_zip_from_files,
    make_png_zip_polyglot,
)

@pytest.fixture
def png_path(tmp_path):
    p = tmp_path / "cover.png"
    Image.new("RGB", (20, 20), (123, 45, 67)).save(p, "PNG")
    return str(p)

@pytest.fixture
def zip_files(tmp_path):
    a = tmp_path / "hello.txt"
    a.write_bytes(b"hello world\n")
    b = tmp_path / "notes.md"
    b.write_bytes(b"# notes\nsome content")
    return [str(a), str(b)]

def test_find_png_end_rejects_non_png():
    with pytest.raises(ValueError):
        _find_png_end(b"not a png")

def test_find_png_end_locates_iend(png_path):
    with open(png_path, "rb") as f:
        data = f.read()
    end = _find_png_end(data)


    assert end == len(data)

def test_polyglot_is_valid_png(png_path, zip_files, tmp_path):
    zip_blob = build_zip_from_files(zip_files)
    out = str(tmp_path / "polyglot.png")
    make_png_zip_polyglot(png_path, zip_blob, output_path=out)


    img = Image.open(out)
    img.load()
    assert img.size == (20, 20)
    assert img.mode == "RGB"

def test_polyglot_is_valid_zip(png_path, zip_files, tmp_path):
    zip_blob = build_zip_from_files(zip_files)
    out = str(tmp_path / "polyglot.png")
    make_png_zip_polyglot(png_path, zip_blob, output_path=out)


    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())
        assert {"hello.txt", "notes.md"} <= names
        assert zf.read("hello.txt") == b"hello world\n"

def test_build_zip_rejects_empty_list():
    with pytest.raises(ValueError):
        build_zip_from_files([])

def test_build_zip_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_zip_from_files([str(tmp_path / "nope.bin")])
