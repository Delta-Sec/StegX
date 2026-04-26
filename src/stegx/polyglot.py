from __future__ import annotations

import io
import logging
import os
import struct
import zipfile
from typing import List, Optional, Tuple

def _find_png_end(data: bytes) -> int:
    sig = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(sig):
        raise ValueError("Input is not a PNG file.")
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        pos += 8 + length + 4
        if ctype == b"IEND":
            return pos
    raise ValueError("PNG has no IEND chunk; refusing to append.")

def build_zip_from_files(paths: List[str]) -> bytes:
    if not paths:
        raise ValueError("Need at least one file to build the ZIP archive.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for path in paths:
            if not os.path.isfile(path):
                raise FileNotFoundError(f"ZIP member not found: {path}")
            arcname = os.path.basename(path) or "file.dat"
            zf.write(path, arcname=arcname)
    return buf.getvalue()

def make_png_zip_polyglot(png_path: str, zip_bytes: bytes, output_path: Optional[str] = None) -> str:
    with open(png_path, "rb") as f:
        png_data = f.read()
    end = _find_png_end(png_data)
    png_prefix = png_data[:end]
    trailing = png_data[end:]
    if trailing:
        logging.warning(
            "Discarding %d bytes of trailing data past PNG IEND before polyglot merge; "
            "any iTXt/tEXt/eXIf appended by upstream editors will be lost.",
            len(trailing),
        )

    shifted_zip = _rebase_zip_offsets(zip_bytes, shift=len(png_prefix))
    polyglot = png_prefix + shifted_zip

    out = output_path or png_path
    with open(out, "wb") as f:
        f.write(polyglot)
    logging.info(
        "PNG+ZIP polyglot written to %s (%d PNG bytes + %d ZIP bytes = %d total)",
        out, len(png_prefix), len(shifted_zip), len(polyglot),
    )
    return out

def _rebase_zip_offsets(zip_bytes: bytes, shift: int) -> bytes:
    if shift == 0:
        return zip_bytes

    cd_offset, cd_size, eocd_pos = _locate_eocd(zip_bytes)
    if cd_offset is None or eocd_pos is None:
        raise ValueError("Could not locate ZIP end-of-central-directory record.")


    prefix = zip_bytes[:cd_offset]
    cd = zip_bytes[cd_offset : cd_offset + cd_size]
    eocd = bytearray(zip_bytes[eocd_pos:])


    patched_cd = bytearray(cd)
    p = 0
    while p + 46 <= len(patched_cd):
        if patched_cd[p : p + 4] != b"PK\x01\x02":
            break
        filename_len = struct.unpack("<H", bytes(patched_cd[p + 28 : p + 30]))[0]
        extra_len = struct.unpack("<H", bytes(patched_cd[p + 30 : p + 32]))[0]
        comment_len = struct.unpack("<H", bytes(patched_cd[p + 32 : p + 34]))[0]
        (lh_offset,) = struct.unpack("<I", bytes(patched_cd[p + 42 : p + 46]))
        patched_cd[p + 42 : p + 46] = struct.pack("<I", lh_offset + shift)
        p += 46 + filename_len + extra_len + comment_len


    (old_cd_off,) = struct.unpack("<I", bytes(eocd[16:20]))
    eocd[16:20] = struct.pack("<I", old_cd_off + shift)

    return prefix + bytes(patched_cd) + bytes(eocd)

def _locate_eocd(zip_bytes: bytes) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    sig = b"PK\x05\x06"
    max_scan = min(len(zip_bytes), 65536 + 22)
    start = len(zip_bytes) - max_scan
    pos = zip_bytes.rfind(sig, start)
    if pos < 0:
        return None, None, None
    (cd_size,) = struct.unpack("<I", zip_bytes[pos + 12 : pos + 16])
    (cd_offset,) = struct.unpack("<I", zip_bytes[pos + 16 : pos + 20])
    return cd_offset, cd_size, pos
