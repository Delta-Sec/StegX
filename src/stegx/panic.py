from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from typing import Iterator, Optional, Sequence, Tuple

from PIL import Image
from PIL.PngImagePlugin import PngInfo

from .decoy import split_regions
from .exceptions import PanicReplaceFailed
from .sentinel import cover_fingerprint

_REPLACE_RETRIES = 5
_REPLACE_SLEEP_S = 0.1

_LOG = logging.getLogger(__name__)


_PANIC_LOCK_STALE_SECONDS = 30


PANIC_FAILURE_SENTINEL_SUFFIX = ".stegx-panic-failed"

def _safe_unlink(path: Optional[str]) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass

def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.GetLastError.restype = wintypes.DWORD
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return kernel32.GetLastError() != 87
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:

        return True

def _try_steal_stale_lock(lock_path: str) -> bool:
    pid = 0
    try:
        fd = os.open(lock_path, os.O_RDONLY)
    except OSError:
        return False
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            return False
        if time.time() - st.st_mtime < _PANIC_LOCK_STALE_SECONDS:
            return False
        try:
            raw = os.read(fd, 128)
        except OSError:
            return False
        try:
            pid = int(raw.decode("ascii", errors="ignore").splitlines()[0].strip() or "0")
        except (ValueError, IndexError):
            pid = 0
        if pid > 0 and _pid_is_alive(pid):
            return False


        try:
            st2 = os.fstat(fd)
        except OSError:
            return False
        if st2.st_mtime != st.st_mtime:
            return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    _safe_unlink(lock_path)
    _LOG.warning(
        "panic: removed stale lock %s (owning PID %d is gone).", lock_path, pid,
    )
    return True

@contextmanager
def _output_lock(output_path: str) -> Iterator[None]:
    lock_path = output_path + ".stegx-lock"
    fd = None
    owned = False
    try:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if _try_steal_stale_lock(lock_path):
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            else:
                _LOG.debug(
                    "panic: output lock %s busy; skipping destruction.", lock_path,
                )
                raise
        owned = True
        payload = f"{os.getpid()}\n{time.time():.3f}"
        os.write(fd, payload.encode("ascii"))
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if owned:
            _safe_unlink(lock_path)

Position = Tuple[int, int, int]

PANIC_MODE_SILENT = "silent"
PANIC_MODE_DECOY = "decoy"
VALID_PANIC_MODES = (PANIC_MODE_SILENT, PANIC_MODE_DECOY)

MATCH_REGION_REAL_FULL = "real-full"
MATCH_REGION_REAL_HALF = "real-half"
MATCH_REGION_DECOY_HALF = "decoy-half"

def destroy_real_region_in_place(
    stego_path: str,
    matched_region_name: str,
    *,
    real_region: Optional[Sequence[Position]] = None,
    decoy_region: Optional[Sequence[Position]] = None,
    panic_mode: str = PANIC_MODE_DECOY,
) -> bool:
    try:
        image = Image.open(stego_path)
        image.load()
    except (OSError, FileNotFoundError) as e:
        _LOG.debug("panic: cannot open stego for destruction: %s", e)
        return False

    try:
        if image.mode == "P":
            image = image.convert("RGBA")
        if image.mode not in ("RGB", "RGBA", "L"):
            return False

        if real_region is None or decoy_region is None:


            from .steganography import _all_positions

            fingerprint = cover_fingerprint(image)
            all_positions = _all_positions(image)
            decoy_region, real_region = split_regions(all_positions, fingerprint)

        if matched_region_name == MATCH_REGION_DECOY_HALF:
            opposite: Sequence = real_region
            matched: Sequence = decoy_region
        elif matched_region_name == MATCH_REGION_REAL_HALF:
            opposite = decoy_region
            matched = real_region
        elif matched_region_name == MATCH_REGION_REAL_FULL:


            _LOG.warning(
                "panic: matched region is real-full but panic requires split "
                "layout; destruction skipped. The panic password may have been "
                "applied to a legacy-v1 or non-split stego."
            )
            return False
        else:
            return False

        _overwrite_lsbs_randomly(image, opposite)


        if panic_mode == PANIC_MODE_SILENT:
            _overwrite_lsbs_randomly(image, matched)


        image.info.clear()


        stego_dir = os.path.dirname(os.path.abspath(stego_path)) or "."
        tmp_path: Optional[str] = None
        try:
            try:
                with _output_lock(stego_path):
                    with tempfile.NamedTemporaryFile(
                        dir=stego_dir, prefix=".stegx_panic_", suffix=".tmp",
                        delete=False,
                    ) as tf:
                        tmp_path = tf.name
                    image.save(
                        tmp_path, format="PNG", pnginfo=PngInfo(),
                        exif=b"", optimize=False,
                    )


                    try:
                        image.close()
                    except Exception:
                        pass


                    _best_effort_shred(stego_path)
                    _atomic_replace(tmp_path, stego_path)
                    tmp_path = None
            except FileExistsError:


                _record_panic_failure(stego_path, reason="lock-busy")
                return False
        except PanicReplaceFailed as e:
            _LOG.debug("panic: atomic replace failed after retries: %s", e)
            _record_panic_failure(stego_path, reason=str(e))
            return False
        except OSError as e:
            _LOG.debug("panic: save-back failed: %s", e)
            _record_panic_failure(stego_path, reason=type(e).__name__)
            return False
        finally:
            _safe_unlink(tmp_path)
        return True
    finally:
        try:
            image.close()
        except Exception:
            pass

def _record_panic_failure(stego_path: str, *, reason: str) -> None:
    path = stego_path + PANIC_FAILURE_SENTINEL_SUFFIX
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{int(time.time())}\t{reason}\n")
    except OSError as e:
        _LOG.debug("panic: could not record failure sentinel %s: %s", path, e)

def _best_effort_shred(path: str) -> None:
    if sys.platform.startswith("win"):
        return
    shred = shutil.which("shred")
    if not shred:
        return
    try:
        subprocess.run(
            [shred, "-u", "-n", "3", path],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as e:
        _LOG.debug("panic: shred invocation failed: %s", e)

def _atomic_replace(src: str, dst: str) -> None:
    last_err: Optional[OSError] = None
    for attempt in range(_REPLACE_RETRIES):
        try:
            os.replace(src, dst)
            return
        except PermissionError as e:
            last_err = e


            if attempt < _REPLACE_RETRIES - 1:
                time.sleep(_REPLACE_SLEEP_S * (attempt + 1))
        except OSError as e:

            raise PanicReplaceFailed(
                f"panic: atomic replace failed: {e}"
            ) from e
    raise PanicReplaceFailed(
        f"panic: atomic replace failed after {_REPLACE_RETRIES} attempts: {last_err}"
    )

def _overwrite_lsbs_randomly(image: Image.Image, positions: Sequence) -> None:
    if not positions:
        return
    pixels = image.load()
    is_gray = image.mode == "L"
    bits = os.urandom((len(positions) + 7) // 8)
    for idx, pos in enumerate(positions):
        x, y, c = pos
        bit = (bits[idx // 8] >> (idx & 7)) & 1
        if is_gray:
            v = pixels[x, y]
            pixels[x, y] = (v & ~1) | bit
        else:
            pixel = list(pixels[x, y])
            pixel[c] = (pixel[c] & ~1) | bit
            pixels[x, y] = tuple(pixel)

def build_panic_payload(
    sacrificial_bytes: bytes,
    sacrificial_filename: str,
    mode: str,
    compression_mode: str,
) -> bytes:
    if mode not in VALID_PANIC_MODES:
        raise ValueError(f"Unknown panic mode: {mode!r}")

    from . import utils

    return utils.create_payload_from_bytes(
        sacrificial_filename,
        sacrificial_bytes,
        compress=True,
        compression_mode=compression_mode,
        panic=True,
        panic_mode=mode,
    )
