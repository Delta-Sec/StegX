from __future__ import annotations

import ctypes
import logging
import sys
from contextlib import contextmanager
from typing import Iterator, Optional, Union

Zeroizable = Union[bytearray, memoryview]

_LOG = logging.getLogger(__name__)


_libc: "Optional[ctypes.CDLL]" = None
_kernel32: "Optional[ctypes.WinDLL]" = None

if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        _libc = None
elif sys.platform == "darwin":
    try:
        _libc = ctypes.CDLL("libc.dylib", use_errno=True)
    except OSError:
        _libc = None
elif sys.platform == "win32":
    try:
        _kernel32 = ctypes.windll.kernel32
    except (OSError, AttributeError):
        _kernel32 = None

if _libc is not None:
    try:
        _libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.mlock.restype = ctypes.c_int
        _libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.munlock.restype = ctypes.c_int
    except AttributeError:
        _libc = None

if _kernel32 is not None:
    try:
        _kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _kernel32.VirtualLock.restype = ctypes.c_bool
        _kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _kernel32.VirtualUnlock.restype = ctypes.c_bool
    except AttributeError:
        _kernel32 = None

def _supports_memory_lock() -> bool:
    return _libc is not None or _kernel32 is not None

MEMORY_LOCK_AVAILABLE = _supports_memory_lock()


def zeroize(buf: Optional[Zeroizable]) -> None:
    if buf is None:
        return
    if isinstance(buf, memoryview):
        if buf.readonly:
            return
        for i in range(len(buf)):
            buf[i] = 0
        return
    if isinstance(buf, bytearray):
        if len(buf) == 0:
            return
        ctypes.memset(
            (ctypes.c_char * len(buf)).from_buffer(buf),
            0,
            len(buf),
        )
        return
    raise TypeError(
        f"Cannot zeroize object of type {type(buf).__name__}; use bytearray."
    )


def _buffer_pointer(buf: bytearray) -> int:
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))

def lock_memory(buf: bytearray) -> bool:
    if not MEMORY_LOCK_AVAILABLE or not isinstance(buf, bytearray) or len(buf) == 0:
        return False
    addr = _buffer_pointer(buf)
    length = len(buf)
    if _libc is not None:
        if _libc.mlock(ctypes.c_void_p(addr), length) == 0:
            return True
        _LOG.debug("mlock(%d bytes) failed: errno=%d", length, ctypes.get_errno())
        return False
    if _kernel32 is not None:
        if _kernel32.VirtualLock(ctypes.c_void_p(addr), length):
            return True
        _LOG.debug("VirtualLock(%d bytes) failed", length)
        return False
    return False

def unlock_memory(buf: bytearray) -> None:
    if not MEMORY_LOCK_AVAILABLE or not isinstance(buf, bytearray) or len(buf) == 0:
        return
    addr = _buffer_pointer(buf)
    length = len(buf)
    if _libc is not None:
        _libc.munlock(ctypes.c_void_p(addr), length)
    elif _kernel32 is not None:
        _kernel32.VirtualUnlock(ctypes.c_void_p(addr), length)


@contextmanager
def Zeroizing(buf: Zeroizable) -> Iterator[Zeroizable]:
    try:
        yield buf
    finally:
        zeroize(buf)

class SecureBuffer:
    __slots__ = ("_buf", "_locked", "_closed")

    def __init__(
        self,
        size: Optional[int] = None,
        *,
        data: Optional[bytes] = None,
    ) -> None:
        if size is None and data is None:
            raise ValueError("Provide either size or data")
        if data is not None:
            self._buf: Optional[bytearray] = bytearray(data)
        else:
            self._buf = bytearray(int(size))
        self._locked = lock_memory(self._buf)
        self._closed = False

    @property
    def buffer(self) -> bytearray:
        if self._closed or self._buf is None:
            raise RuntimeError("SecureBuffer has been closed.")
        return self._buf

    @property
    def locked(self) -> bool:
        return self._locked

    def __enter__(self) -> bytearray:
        return self.buffer

    def __exit__(self, *_args) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            buf = self._buf
            if buf is not None:
                zeroize(buf)
                if self._locked:
                    unlock_memory(buf)
                    self._locked = False
        finally:
            self._buf = None
            self._closed = True

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

def to_mutable_bytes(data: Union[bytes, bytearray, str]) -> bytearray:
    if isinstance(data, str):
        return bytearray(data.encode("utf-8"))
    return bytearray(data)

__all__ = [
    "MEMORY_LOCK_AVAILABLE",
    "SecureBuffer",
    "Zeroizing",
    "lock_memory",
    "to_mutable_bytes",
    "unlock_memory",
    "zeroize",
]
