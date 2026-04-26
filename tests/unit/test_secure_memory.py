
import pytest

from stegx.secure_memory import (
    MEMORY_LOCK_AVAILABLE,
    SecureBuffer,
    Zeroizing,
    lock_memory,
    to_mutable_bytes,
    unlock_memory,
    zeroize,
)

def test_zeroize_bytearray():
    buf = bytearray(b"sensitive data")
    zeroize(buf)
    assert bytes(buf) == b"\x00" * len(buf)

def test_zeroize_ignores_none():
    zeroize(None)

def test_zeroize_rejects_immutable_bytes():
    with pytest.raises(TypeError):
        zeroize(b"cannot zero a bytes object")

def test_zeroizing_context_manager():
    buf = bytearray(b"secret")
    with Zeroizing(buf) as b:
        assert bytes(b) == b"secret"
    assert bytes(buf) == b"\x00\x00\x00\x00\x00\x00"

def test_zeroizing_clears_on_exception():
    buf = bytearray(b"boom")
    with pytest.raises(RuntimeError):
        with Zeroizing(buf):
            raise RuntimeError("kaboom")
    assert bytes(buf) == b"\x00\x00\x00\x00"

def test_memory_lock_availability_flag_is_bool():
    assert isinstance(MEMORY_LOCK_AVAILABLE, bool)

def test_lock_memory_is_best_effort():
    buf = bytearray(64)
    locked = lock_memory(buf)
    assert isinstance(locked, bool)
    if locked:
        unlock_memory(buf)

def test_lock_memory_rejects_non_bytearray():
    assert lock_memory(b"") is False

def test_secure_buffer_zeroises_on_close():
    sb = SecureBuffer(data=b"key material")
    assert bytes(sb.buffer) == b"key material"
    sb.close()
    with pytest.raises(RuntimeError):
        _ = sb.buffer

def test_secure_buffer_context_manager():
    with SecureBuffer(data=b"ephemeral key") as key:
        assert key == bytearray(b"ephemeral key")


def test_secure_buffer_with_size():
    sb = SecureBuffer(32)
    assert len(sb.buffer) == 32
    sb.close()

def test_secure_buffer_double_close_is_idempotent():
    sb = SecureBuffer(data=b"once")
    sb.close()
    sb.close()

def test_secure_buffer_requires_arg():
    with pytest.raises(ValueError):
        SecureBuffer()

def test_to_mutable_bytes_string():
    buf = to_mutable_bytes("hello")
    assert isinstance(buf, bytearray)
    assert bytes(buf) == b"hello"

def test_to_mutable_bytes_bytes():
    buf = to_mutable_bytes(b"\x00\x01\x02")
    assert bytes(buf) == b"\x00\x01\x02"
