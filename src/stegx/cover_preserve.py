from __future__ import annotations

import logging
import os
import struct
import tempfile
import zlib
from dataclasses import dataclass
from typing import Optional

from PIL import Image
from PIL.PngImagePlugin import PngInfo

@dataclass
class CoverEncoderParams:
    compress_level: int = 6
    bits: Optional[int] = None

def sniff_png_encoder(path: str) -> CoverEncoderParams:
    params = CoverEncoderParams()
    try:
        with open(path, "rb") as f:
            sig = f.read(8)
            if sig[:8] != b"\x89PNG\r\n\x1a\n":
                return params
            while True:
                header = f.read(8)
                if len(header) < 8:
                    break
                length = struct.unpack(">I", header[:4])[0]
                ctype = header[4:8]
                data = f.read(length)
                f.read(4)
                if ctype == b"IHDR" and len(data) >= 9:
                    params.bits = data[8]
                elif ctype == b"IDAT":
                    if data:
                        flevel = (data[1] >> 6) & 0x03
                        params.compress_level = {0: 1, 1: 3, 2: 6, 3: 9}.get(flevel, 6)
                    break
                elif ctype == b"IEND":
                    break
    except (OSError, struct.error, zlib.error) as e:
        logging.debug("Could not sniff cover PNG encoder params: %s", e)
    return params


_REPLACE_RETRIES = 5
_REPLACE_SLEEP_S = 0.1

def _atomic_replace(src: str, dst: str) -> None:
    import time as _time

    last_err: Optional[OSError] = None
    for attempt in range(_REPLACE_RETRIES):
        try:
            os.replace(src, dst)
            return
        except PermissionError as e:
            last_err = e
            if attempt < _REPLACE_RETRIES - 1:
                _time.sleep(_REPLACE_SLEEP_S * (attempt + 1))
        except OSError:


            raise
    if last_err is not None:
        raise last_err

def _fsync_path(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError as e:
        logging.debug("fsync of %s failed (best-effort): %s", path, e)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

def _fsync_dir(path: str) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError as e:
        logging.debug("fsync of directory %s failed (best-effort): %s", path, e)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

def save_as_stego_png(
    image: Image.Image,
    output_path: str,
    encoder_params: CoverEncoderParams,
    preserve: bool = True,
) -> None:
    pnginfo = PngInfo()
    save_kwargs = {
        "format": "PNG",
        "pnginfo": pnginfo,
        "optimize": False,
    }
    if preserve:
        save_kwargs["compress_level"] = int(encoder_params.compress_level)

    out_dir = os.path.dirname(os.path.abspath(output_path)) or "."


    fd, tmp_path = tempfile.mkstemp(
        dir=out_dir, prefix=".stegx_save_", suffix=".tmp.png"
    )
    os.close(fd)
    try:
        image.save(tmp_path, **save_kwargs)
        _fsync_path(tmp_path)
        _atomic_replace(tmp_path, output_path)
        tmp_path = None
        _fsync_dir(out_dir)
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logging.debug("Could not remove stego tempfile %s: %s", tmp_path, e)
