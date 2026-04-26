from __future__ import annotations

import bz2
import logging
import lzma
import zlib
from typing import Callable, Dict, List, Optional, Tuple

from .exceptions import DecompressionBombError
from .fips import ban_if_fips, is_fips_active

_CompressorFn = Callable[[bytes], Optional[bytes]]


MAX_DECOMPRESS_SIZE = 256 * 1024 * 1024

ALG_NONE = "none"
ALG_ZLIB = "zlib"
ALG_LZMA = "lzma"
ALG_BZ2 = "bz2"
ALG_ZSTD = "zstd"
ALG_ZSTD_DICT = "zstd_dict_v1"
ALG_BROTLI = "brotli"

_LZMA_FILTERS = [
    {"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME}
]

MODE_FAST = "fast"
MODE_BEST = "best"
VALID_MODES = (MODE_FAST, MODE_BEST)


_FIPS_ALLOWED_ALGS = {ALG_NONE, ALG_ZLIB}

def _fips_check_alg(alg_name: str) -> None:
    if alg_name not in _FIPS_ALLOWED_ALGS:
        ban_if_fips(f"compression algorithm {alg_name!r}")

def _compress_zlib(data: bytes) -> bytes:
    return zlib.compress(data, 9)

def _compress_lzma(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=_LZMA_FILTERS)

def _compress_bz2(data: bytes) -> bytes:
    return bz2.compress(data, compresslevel=9)

def _compress_zstd(data: bytes) -> Optional[bytes]:
    try:
        import zstandard
    except ImportError:
        return None
    cctx = zstandard.ZstdCompressor(
        level=22,
        write_content_size=False,
        write_checksum=False,
    )
    return cctx.compress(data)

_ZSTD_DICT_CACHE: "Optional[object]" = None

def _load_zstd_dict() -> "Optional[object]":
    global _ZSTD_DICT_CACHE
    if _ZSTD_DICT_CACHE is not None:
        return _ZSTD_DICT_CACHE
    try:
        import zstandard
    except ImportError:
        return None
    from pathlib import Path

    dict_path = Path(__file__).resolve().parent / "data" / "stegx_dict_v1.zstd"
    if not dict_path.is_file():
        return None
    try:
        blob = dict_path.read_bytes()
        _ZSTD_DICT_CACHE = zstandard.ZstdCompressionDict(blob)
        return _ZSTD_DICT_CACHE
    except Exception as e:
        logging.debug("Could not load zstd dictionary %s: %s", dict_path, e)
        return None

def _compress_zstd_dict(data: bytes) -> Optional[bytes]:
    zdict = _load_zstd_dict()
    if zdict is None:
        return None
    try:
        import zstandard
    except ImportError:
        return None
    cctx = zstandard.ZstdCompressor(
        level=22,
        write_content_size=False,
        write_checksum=False,
        dict_data=zdict,
    )
    return cctx.compress(data)

def _decompress_zstd_dict(blob: bytes) -> bytes:
    zdict = _load_zstd_dict()
    if zdict is None:
        raise ValueError("Bundled zstd dictionary is not available.")
    import io

    import zstandard

    dctx = zstandard.ZstdDecompressor(dict_data=zdict)
    with dctx.stream_reader(io.BytesIO(blob)) as rdr:
        result = rdr.read(MAX_DECOMPRESS_SIZE + 1)
        if len(result) > MAX_DECOMPRESS_SIZE:
            raise DecompressionBombError(f"Decompressed output exceeds safety limit ({MAX_DECOMPRESS_SIZE} bytes).")
        return result

def _compress_brotli(data: bytes) -> Optional[bytes]:
    try:
        import brotli
    except ImportError:
        return None
    return brotli.compress(data, quality=11)


def _compress_zstd_safe(data: bytes) -> Optional[bytes]:
    return _compress_zstd(data)

def _compress_brotli_safe(data: bytes) -> Optional[bytes]:
    return _compress_brotli(data)

def _compress_zstd_dict_safe(data: bytes) -> Optional[bytes]:
    return _compress_zstd_dict(data)


_STREAM_CHUNK = 64 * 1024

def _raise_bomb() -> None:
    raise DecompressionBombError(
        f"Decompressed output exceeds safety limit ({MAX_DECOMPRESS_SIZE} bytes)."
    )

def _bounded_stream_stdlib(decomp, blob: bytes) -> bytes:
    out = bytearray()
    cap = MAX_DECOMPRESS_SIZE
    view = memoryview(blob)
    offset = 0
    while offset < len(view):
        chunk = bytes(view[offset : offset + _STREAM_CHUNK])
        offset += len(chunk)
        remaining = cap - len(out) + 1
        if remaining <= 0:
            _raise_bomb()
        piece = decomp.decompress(chunk, remaining)
        out.extend(piece)
        if len(out) > cap:
            _raise_bomb()


        while not decomp.needs_input and not getattr(decomp, "eof", False):
            remaining = cap - len(out) + 1
            if remaining <= 0:
                _raise_bomb()
            piece = decomp.decompress(b"", remaining)
            if not piece:
                break
            out.extend(piece)
            if len(out) > cap:
                _raise_bomb()
    return bytes(out)

def _decompress_zstd(blob: bytes) -> bytes:
    import io

    import zstandard

    dctx = zstandard.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(blob)) as rdr:


        result = rdr.read(MAX_DECOMPRESS_SIZE + 1)
        if len(result) > MAX_DECOMPRESS_SIZE:
            _raise_bomb()
        return result

def _decompress_brotli(blob: bytes) -> bytes:
    import brotli


    Decompressor = getattr(brotli, "Decompressor", None)
    if Decompressor is None:


        result = brotli.decompress(blob)
        if len(result) > MAX_DECOMPRESS_SIZE:
            _raise_bomb()
        return result

    decomp = Decompressor()
    out = bytearray()
    cap = MAX_DECOMPRESS_SIZE
    view = memoryview(blob)
    offset = 0
    while offset < len(view):
        chunk = bytes(view[offset : offset + _STREAM_CHUNK])
        offset += len(chunk)
        piece = decomp.process(chunk)
        out.extend(piece)
        if len(out) > cap:
            _raise_bomb()
    if not decomp.is_finished():


        raise DecompressionBombError(
            "brotli stream truncated or ran past safety limit."
        )
    return bytes(out)

def _decompress_zlib_safe(blob: bytes) -> bytes:
    decomp = zlib.decompressobj()
    out = bytearray()
    cap = MAX_DECOMPRESS_SIZE
    view = memoryview(blob)
    offset = 0
    pending = b""
    while offset < len(view) or pending:
        if pending:
            chunk = pending
        else:
            chunk = bytes(view[offset : offset + _STREAM_CHUNK])
            offset += len(chunk)
        remaining = cap - len(out) + 1
        if remaining <= 0:
            _raise_bomb()
        piece = decomp.decompress(chunk, remaining)
        out.extend(piece)
        if len(out) > cap:
            _raise_bomb()
        pending = decomp.unconsumed_tail
    tail = decomp.flush(max(cap - len(out) + 1, 1))
    out.extend(tail)
    if len(out) > cap:
        _raise_bomb()
    return bytes(out)

def _decompress_lzma_safe(blob: bytes) -> bytes:
    decomp = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=_LZMA_FILTERS)
    return _bounded_stream_stdlib(decomp, blob)

def _decompress_bz2_safe(blob: bytes) -> bytes:
    decomp = bz2.BZ2Decompressor()
    return _bounded_stream_stdlib(decomp, blob)

_DECOMPRESSORS = {
    ALG_NONE: lambda b: b,
    ALG_ZLIB: _decompress_zlib_safe,
    ALG_LZMA: _decompress_lzma_safe,
    ALG_BZ2: _decompress_bz2_safe,
    ALG_ZSTD: _decompress_zstd,
    ALG_ZSTD_DICT: _decompress_zstd_dict,
    ALG_BROTLI: _decompress_brotli,
}

def available_algorithms() -> List[str]:
    present = [ALG_NONE, ALG_ZLIB, ALG_LZMA, ALG_BZ2]
    try:
        import zstandard

        present.append(ALG_ZSTD)
        if _load_zstd_dict() is not None:
            present.append(ALG_ZSTD_DICT)
    except ImportError:
        pass
    try:
        import brotli

        present.append(ALG_BROTLI)
    except ImportError:
        pass
    return present

def compress_best(
    data: bytes,
    mode: str = MODE_BEST,
    show_progress: bool = False,
) -> Tuple[str, bytes]:
    if mode not in VALID_MODES:
        raise ValueError(f"Unknown compression mode: {mode!r}")

    codec_plan: List[Tuple[str, "_CompressorFn"]] = [(ALG_ZLIB, _compress_zlib)]
    if mode == MODE_BEST:
        codec_plan.extend(
            [
                (ALG_LZMA, _compress_lzma),
                (ALG_BZ2, _compress_bz2),
                (ALG_ZSTD, _compress_zstd_safe),
                (ALG_ZSTD_DICT, _compress_zstd_dict_safe),
                (ALG_BROTLI, _compress_brotli_safe),
            ]
        )


    if is_fips_active():
        codec_plan = [
            (name, fn) for (name, fn) in codec_plan if name in _FIPS_ALLOWED_ALGS
        ]

    bar = None
    if show_progress and len(data) >= 4096:
        try:
            from tqdm import tqdm

            bar = tqdm(
                total=len(codec_plan),
                desc=f"compress {len(data)} B",
                unit="codec",
                leave=False,
            )
        except ImportError:
            bar = None

    candidates: List[Tuple[str, bytes]] = [(ALG_NONE, data)]
    for alg_name, fn in codec_plan:
        if bar is not None:
            bar.set_postfix_str(alg_name, refresh=False)
        try:
            blob = fn(data)
        except Exception as e:
            logging.debug("%s compression failed: %s", alg_name, e)
            blob = None
        if blob is not None:
            candidates.append((alg_name, blob))
        if bar is not None:
            bar.update(1)
    if bar is not None:
        bar.close()

    alg_priority: Dict[str, int] = {
        ALG_NONE: 0,
        ALG_ZLIB: 1,
        ALG_LZMA: 2,
        ALG_BZ2: 3,
        ALG_ZSTD: 4,
        ALG_ZSTD_DICT: 5,
        ALG_BROTLI: 6,
    }
    candidates.sort(key=lambda pair: (len(pair[1]), alg_priority.get(pair[0], 99)))
    best_alg, best_blob = candidates[0]

    if logging.getLogger().isEnabledFor(logging.DEBUG):
        summary = ", ".join(f"{name}={len(blob)}" for name, blob in candidates)
        logging.debug("compression candidates: %s → winner=%s (%d B)",
                      summary, best_alg, len(best_blob))

    return best_alg, best_blob

def decompress(alg_name: str, blob: bytes) -> bytes:
    try:
        fn = _DECOMPRESSORS[alg_name]
    except KeyError as e:
        raise ValueError(f"Unknown compression algorithm: {alg_name!r}") from e


    _fips_check_alg(alg_name)
    return fn(blob)

def ratio_report(original: int, compressed: int) -> str:
    pct = (100.0 * compressed / original) if original else 0.0
    return f"{original:,} -> {compressed:,} B ({pct:.1f}% of original)"
