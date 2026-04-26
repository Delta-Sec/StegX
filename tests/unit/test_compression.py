
import os

import pytest

from stegx.compression import (
    ALG_BROTLI,
    ALG_BZ2,
    ALG_LZMA,
    ALG_NONE,
    ALG_ZLIB,
    ALG_ZSTD,
    MODE_BEST,
    MODE_FAST,
    available_algorithms,
    compress_best,
    decompress,
    ratio_report,
)

@pytest.fixture
def text_data():
    return (b"The quick brown fox jumps over the lazy dog. " * 200)

@pytest.fixture
def binary_data():
    return os.urandom(16) + bytes(range(256)) * 40 + b"\x00" * 500

def test_roundtrip_text(text_data):
    alg, blob = compress_best(text_data, mode=MODE_BEST)
    assert alg != ALG_NONE
    assert len(blob) < len(text_data)
    assert decompress(alg, blob) == text_data

def test_roundtrip_binary(binary_data):
    alg, blob = compress_best(binary_data, mode=MODE_BEST)
    assert decompress(alg, blob) == binary_data

@pytest.mark.parametrize("size", [1, 10, 100, 1024, 16_384])
def test_roundtrip_random_sizes(size):
    data = os.urandom(size)
    alg, blob = compress_best(data, mode=MODE_BEST)
    assert decompress(alg, blob) == data

def test_none_wins_for_incompressible(binary_data):

    incompressible = os.urandom(32)
    alg, blob = compress_best(incompressible, mode=MODE_BEST)
    assert alg == ALG_NONE
    assert blob == incompressible

def test_best_beats_or_ties_fast(text_data):
    _, fast_blob = compress_best(text_data, mode=MODE_FAST)
    _, best_blob = compress_best(text_data, mode=MODE_BEST)
    assert len(best_blob) <= len(fast_blob)

def test_fast_mode_limits_to_zlib(text_data):
    alg, _ = compress_best(text_data, mode=MODE_FAST)
    assert alg in (ALG_NONE, ALG_ZLIB)

def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        compress_best(b"xx", mode="ultra-mega")

def test_unknown_alg_decompress_raises():
    with pytest.raises(ValueError):
        decompress("not-a-codec", b"\x00")

def test_available_algorithms_has_stdlib():
    present = set(available_algorithms())
    assert {ALG_NONE, ALG_ZLIB, ALG_LZMA, ALG_BZ2} <= present

def test_zstd_dict_roundtrip_if_available():
    present = set(available_algorithms())
    if "zstd_dict_v1" not in present:
        pytest.skip("zstd dictionary not available in this environment")
    payload = b'{"status":"ok","user":"alice","role":"admin"}'

    alg, blob = compress_best(payload)
    assert decompress(alg, blob) == payload

def test_zstd_dict_wins_on_small_json():
    present = set(available_algorithms())
    if "zstd_dict_v1" not in present:
        pytest.skip("zstd dictionary not available in this environment")
    import zstandard

    dict_path = __import__("pathlib").Path(
        __import__("stegx").compression.__file__
    ).parent / "data" / "stegx_dict_v1.zstd"
    zdict = zstandard.ZstdCompressionDict(dict_path.read_bytes())
    sample = b'{"version":"1.0","name":"sample","items":[{"id":1,"value":"hello"}]}'
    plain = zstandard.ZstdCompressor(level=22).compress(sample)
    with_dict = zstandard.ZstdCompressor(level=22, dict_data=zdict).compress(sample)
    assert len(with_dict) <= len(plain)

def test_decompress_each_stdlib_alg(text_data):
    for alg in (ALG_ZLIB, ALG_LZMA, ALG_BZ2):
        _, blob = compress_best(text_data, mode=MODE_BEST)


    import bz2, lzma, zlib

    assert decompress(ALG_ZLIB, zlib.compress(text_data, 9)) == text_data
    assert decompress(ALG_BZ2, bz2.compress(text_data, 9)) == text_data
    filters = [{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME}]
    lzma_blob = lzma.compress(text_data, format=lzma.FORMAT_RAW, filters=filters)
    assert decompress(ALG_LZMA, lzma_blob) == text_data

def test_ratio_report_format():
    r = ratio_report(1000, 200)
    assert "1,000" in r
    assert "200" in r
    assert "20.0" in r

def test_empty_payload_returns_none():

    alg, blob = compress_best(b"x", mode=MODE_BEST)
    assert alg == ALG_NONE
    assert blob == b"x"


from stegx.compression import MAX_DECOMPRESS_SIZE
from stegx.exceptions import DecompressionBombError

def _build_zlib_bomb(size: int) -> bytes:
    import zlib as _zlib
    return _zlib.compress(b"\x00" * size, 9)

def _build_lzma_bomb(size: int) -> bytes:
    import lzma as _lzma
    filters = [{"id": _lzma.FILTER_LZMA2, "preset": 9 | _lzma.PRESET_EXTREME}]
    return _lzma.compress(b"\x00" * size, format=_lzma.FORMAT_RAW, filters=filters)

def _build_bz2_bomb(size: int) -> bytes:
    import bz2 as _bz2
    return _bz2.compress(b"\x00" * size, 9)


_TEST_CAP = 64 * 1024

@pytest.fixture
def small_cap(monkeypatch):
    import stegx.compression as _cx_mod

    monkeypatch.setattr(_cx_mod, "MAX_DECOMPRESS_SIZE", _TEST_CAP)
    yield _TEST_CAP

@pytest.mark.parametrize(
    "alg,builder",
    [
        (ALG_ZLIB, _build_zlib_bomb),
        (ALG_LZMA, _build_lzma_bomb),
        (ALG_BZ2, _build_bz2_bomb),
    ],
)
def test_streaming_decompress_accepts_exact_cap(small_cap, alg, builder):
    blob = builder(small_cap)
    out = decompress(alg, blob)
    assert len(out) == small_cap
    assert out == b"\x00" * small_cap

@pytest.mark.parametrize(
    "alg,builder",
    [
        (ALG_ZLIB, _build_zlib_bomb),
        (ALG_LZMA, _build_lzma_bomb),
        (ALG_BZ2, _build_bz2_bomb),
    ],
)
def test_streaming_decompress_rejects_bomb(small_cap, alg, builder):
    blob = builder(small_cap + 1)
    with pytest.raises(DecompressionBombError):
        decompress(alg, blob)

def test_streaming_brotli_rejects_bomb_if_available(small_cap):
    if ALG_BROTLI not in available_algorithms():
        pytest.skip("brotli not installed in this environment")
    import brotli as _brotli

    bomb = _brotli.compress(b"\x00" * (small_cap + 1))
    with pytest.raises(DecompressionBombError):
        decompress(ALG_BROTLI, bomb)

def test_mod_level_max_cap_is_256_mib_by_default():
    import stegx.compression as _cx_mod

    assert _cx_mod.MAX_DECOMPRESS_SIZE == 256 * 1024 * 1024
