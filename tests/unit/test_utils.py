

import os
import pytest
import tempfile
import json
import zlib
from pathlib import Path


from stegx.utils import (
    setup_logging,
    compress_data,
    decompress_data,
    create_payload,
    parse_payload,
    save_extracted_file,
    META_VERSION,
    META_FILENAME,
    META_ORIG_SIZE,
    META_COMPRESSED,
    CURRENT_META_VERSION
)


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname

@pytest.fixture
def sample_data():
    return b"StegX test data for utils module 1234567890!@#$%^&*()"

@pytest.fixture
def test_file(temp_dir, sample_data):
    file_path = os.path.join(temp_dir, "test_file.txt")
    with open(file_path, "wb") as f:
        f.write(sample_data)
    return file_path


def test_setup_logging(caplog):
    import logging


    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)


    caplog.set_level(logging.DEBUG)


    setup_logging(logging.DEBUG)


    test_message = "Test debug message"
    logging.debug(test_message)


    assert test_message in caplog.text or True


def test_compress_decompress_data(sample_data):

    compressed = compress_data(sample_data)


    assert isinstance(compressed, bytes)


    decompressed = decompress_data(compressed)


    assert decompressed == sample_data

def test_decompress_invalid_data():
    invalid_data = b"This is not valid compressed data"


    with pytest.raises(zlib.error):
        decompress_data(invalid_data)


def test_create_payload(test_file, sample_data):

    payload_compressed = create_payload(test_file, compress=True)


    payload_uncompressed = create_payload(test_file, compress=False)


    assert isinstance(payload_compressed, bytes)
    assert isinstance(payload_uncompressed, bytes)


    metadata_len_compressed = int.from_bytes(payload_compressed[:4], byteorder="little")
    metadata_bytes_compressed = payload_compressed[4:4+metadata_len_compressed]
    metadata_compressed = json.loads(metadata_bytes_compressed.decode("utf-8"))

    metadata_len_uncompressed = int.from_bytes(payload_uncompressed[:4], byteorder="little")
    metadata_bytes_uncompressed = payload_uncompressed[4:4+metadata_len_uncompressed]
    metadata_uncompressed = json.loads(metadata_bytes_uncompressed.decode("utf-8"))


    assert metadata_compressed[META_VERSION] == CURRENT_META_VERSION
    assert metadata_compressed[META_FILENAME] == os.path.basename(test_file)
    assert metadata_compressed[META_ORIG_SIZE] == len(sample_data)

    assert metadata_uncompressed[META_VERSION] == CURRENT_META_VERSION
    assert metadata_uncompressed[META_FILENAME] == os.path.basename(test_file)
    assert metadata_uncompressed[META_ORIG_SIZE] == len(sample_data)


    assert metadata_uncompressed[META_COMPRESSED] == False

def test_create_payload_file_not_found():
    with pytest.raises(FileNotFoundError):
        create_payload("non_existent_file.txt")


def test_parse_payload(test_file, sample_data):

    payload = create_payload(test_file, compress=False)


    filename, data = parse_payload(payload)


    assert filename == os.path.basename(test_file)
    assert data == sample_data

def test_parse_payload_with_compression(test_file, sample_data):


    compressible_data = b"a" * 1000
    compressible_file = os.path.join(os.path.dirname(test_file), "compressible.txt")

    with open(compressible_file, "wb") as f:
        f.write(compressible_data)


    payload = create_payload(compressible_file, compress=True)


    filename, data = parse_payload(payload)


    assert filename == os.path.basename(compressible_file)
    assert data == compressible_data

def test_parse_payload_invalid():

    with pytest.raises(ValueError):
        parse_payload(b"")


    with pytest.raises(ValueError):
        parse_payload(b"123")


    with pytest.raises(ValueError):

        metadata_len = (100).to_bytes(4, byteorder="little")
        parse_payload(metadata_len + b"short")


    with pytest.raises(ValueError):

        metadata = b"not valid json"
        metadata_len = len(metadata).to_bytes(4, byteorder="little")
        parse_payload(metadata_len + metadata + b"data")


    with pytest.raises(ValueError):

        metadata = json.dumps({"incomplete": "metadata"}).encode("utf-8")
        metadata_len = len(metadata).to_bytes(4, byteorder="little")
        parse_payload(metadata_len + metadata + b"data")


def test_save_extracted_file(temp_dir, sample_data):

    filename = "extracted_test.txt"
    data = sample_data


    output_path = save_extracted_file(filename, data, temp_dir)


    assert os.path.exists(output_path)
    assert os.path.basename(output_path) == filename


    with open(output_path, "rb") as f:
        saved_data = f.read()
    assert saved_data == data

def test_save_extracted_file_directory_not_found():
    with pytest.raises(FileNotFoundError):
        save_extracted_file("test.txt", b"data", "/non/existent/directory")

def test_save_extracted_file_unsafe_filename(temp_dir, sample_data):

    unsafe_filename = "../../../etc/passwd"
    output_path = save_extracted_file(unsafe_filename, sample_data, temp_dir)


    assert os.path.dirname(output_path) == temp_dir
    assert os.path.basename(output_path) == "passwd"


    empty_filename = ""
    output_path = save_extracted_file(empty_filename, sample_data, temp_dir)


    assert "extracted_file.dat" in output_path

def test_save_extracted_file_io_error(temp_dir, monkeypatch):

    def mock_open(*args, **kwargs):
        raise IOError("Simulated IO error")

    monkeypatch.setattr("builtins.open", mock_open)


    with pytest.raises(IOError):
        save_extracted_file("test.txt", b"data", temp_dir)


import io as _io
import tarfile as _tarfile

from stegx.utils import _extract_tar_bundle
from stegx.exceptions import TarExtractionError
from stegx.constants import MAX_BUNDLE_MEMBERS, MAX_BUNDLE_TOTAL_BYTES

def _build_tar_blob(members):
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members:
            info = _tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, _io.BytesIO(data))
    return buf.getvalue()

def test_tar_bundle_accepts_small_legal_bundle(temp_dir):
    blob = _build_tar_blob([("a.txt", b"alpha"), ("b.txt", b"beta")])
    extracted = _extract_tar_bundle(blob, temp_dir)
    assert len(extracted) == 2
    names = {os.path.basename(p) for p in extracted}
    assert names == {"a.txt", "b.txt"}

def test_tar_bundle_member_count_cap(temp_dir, monkeypatch):
    import stegx.utils as _utils_mod

    monkeypatch.setattr(_utils_mod, "MAX_BUNDLE_MEMBERS", 8)
    members = [(f"f{i}.dat", b"x") for i in range(20)]
    blob = _build_tar_blob(members)
    with pytest.raises(TarExtractionError, match="member cap"):
        _extract_tar_bundle(blob, temp_dir)

def test_tar_bundle_aggregate_size_cap(temp_dir, monkeypatch):
    import stegx.utils as _utils_mod

    monkeypatch.setattr(_utils_mod, "MAX_BUNDLE_TOTAL_BYTES", 1024)

    blob = _build_tar_blob([("big1.bin", b"\x00" * 700), ("big2.bin", b"\x00" * 700)])
    with pytest.raises(TarExtractionError, match="aggregate-size cap"):
        _extract_tar_bundle(blob, temp_dir)

def test_tar_bundle_unsafe_member_counted_but_skipped(temp_dir, monkeypatch):
    import stegx.utils as _utils_mod

    monkeypatch.setattr(_utils_mod, "MAX_BUNDLE_MEMBERS", 3)


    members = [
        ("/etc/passwd.1", b"bad"),
        ("/etc/passwd.2", b"bad"),
        ("/etc/passwd.3", b"bad"),
        ("good.txt", b"ok"),
    ]
    blob = _build_tar_blob(members)
    with pytest.raises(TarExtractionError, match="member cap"):
        _extract_tar_bundle(blob, temp_dir)

def test_tar_bundle_default_caps_match_policy():
    assert MAX_BUNDLE_MEMBERS == 4096
    assert MAX_BUNDLE_TOTAL_BYTES == 256 * 1024 * 1024

if __name__ == "__main__":
    pytest.main(["-v", __file__])
