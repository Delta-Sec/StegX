from __future__ import annotations

import io
import ipaddress
import json
import os
import struct
import tempfile

import pytest

from stegx.audit_log import append_record, resolve_or_create_audit_key, verify_chain
from stegx.exceptions import (
    EmptyPayloadError,
    FipsPolicyViolation,
    HeaderParameterOutOfRange,
    PanicReplaceFailed,
)
from stegx.header import Header
from stegx.kdf import KdfParams


def _pack_argon2_header_raw(time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    MAGIC = 0x58
    VERSION = 0x02
    KDF_ARGON2ID = 0x02
    flags = 0
    kdf_blob = struct.pack(">BIB2x", time_cost & 0xFF, memory_kib & 0xFFFFFFFF, parallelism & 0xFF)
    salt = b"\x00" * 16
    aes_nonce = b"\x00" * 12
    chacha_nonce = b"\x00" * 12
    inner_len = 0
    return struct.pack(
        ">BBBB8s16s12s12sI",
        MAGIC, VERSION, KDF_ARGON2ID, flags,
        kdf_blob, salt, aes_nonce, chacha_nonce, inner_len,
    )

@pytest.mark.security
def test_header_rejects_argon2_memory_overflow():

    buf = _pack_argon2_header_raw(time_cost=3, memory_kib=4 * 1024 * 1024, parallelism=4)
    with pytest.raises(HeaderParameterOutOfRange):
        Header.unpack(buf)

@pytest.mark.security
def test_header_rejects_argon2_time_cost_overflow():
    buf = _pack_argon2_header_raw(time_cost=200, memory_kib=65536, parallelism=4)
    with pytest.raises(HeaderParameterOutOfRange):
        Header.unpack(buf)

@pytest.mark.security
def test_header_accepts_normal_argon2_params():
    buf = _pack_argon2_header_raw(time_cost=3, memory_kib=65536, parallelism=4)
    h = Header.unpack(buf)
    assert h.kdf.memory_cost_kib == 65536


@pytest.mark.security
def test_ssrf_denies_aws_imds():
    from stegx.io_sources import _is_safe_ip
    assert _is_safe_ip(ipaddress.ip_address("169.254.169.254")) is False

@pytest.mark.security
def test_ssrf_denies_rfc1918():
    from stegx.io_sources import _is_safe_ip
    for a in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        assert _is_safe_ip(ipaddress.ip_address(a)) is False, a

@pytest.mark.security
def test_ssrf_denies_loopback_and_linklocal():
    from stegx.io_sources import _is_safe_ip
    for a in ("127.0.0.1", "::1", "169.254.1.1", "fe80::1"):
        assert _is_safe_ip(ipaddress.ip_address(a)) is False, a

@pytest.mark.security
def test_ssrf_denies_cgnat():
    from stegx.io_sources import _is_safe_ip
    assert _is_safe_ip(ipaddress.ip_address("100.64.1.1")) is False

@pytest.mark.security
def test_ssrf_denies_ipv4_mapped_ipv6():
    from stegx.io_sources import _is_safe_ip


    assert _is_safe_ip(ipaddress.ip_address("::ffff:127.0.0.1")) is False

@pytest.mark.security
def test_ssrf_allows_public_address():
    from stegx.io_sources import _is_safe_ip
    assert _is_safe_ip(ipaddress.ip_address("1.1.1.1")) is True


@pytest.mark.security
def test_parse_payload_warning_does_not_crash_on_size_mismatch(caplog):
    from stegx.utils import create_payload_from_bytes, parse_payload_full

    payload = create_payload_from_bytes("x.bin", b"abc", compress=False)


    hdr_len = int.from_bytes(payload[:4], "little")
    meta = json.loads(payload[4:4 + hdr_len].decode())
    meta["original_size"] = 999
    new_meta = json.dumps(meta, ensure_ascii=False).encode()
    tampered = len(new_meta).to_bytes(4, "little") + new_meta + payload[4 + hdr_len:]
    filename, data, _meta = parse_payload_full(tampered)
    assert filename == "x.bin"
    assert data == b"abc"


@pytest.mark.security
def test_audit_log_hmacs_by_default_and_verifies(tmp_path, monkeypatch):


    monkeypatch.setenv("STEGX_CONFIG_HOME", str(tmp_path))
    log_path = str(tmp_path / "audit.log")
    assert append_record(log_path, "encode", ok=True, flags=["--adaptive"]) is True
    assert append_record(log_path, "decode", ok=True) is True

    key = resolve_or_create_audit_key()
    intact, count, bad = verify_chain(log_path, hmac_key=key)
    assert intact is True
    assert count == 2
    assert bad is None


    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec = json.loads(lines[0])
    rec["note"] = "tampered"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    intact2, _, bad2 = verify_chain(log_path, hmac_key=key)
    assert intact2 is False
    assert bad2 == 1

@pytest.mark.security
def test_audit_log_verify_without_hmac_key_still_catches_chain_break(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGX_CONFIG_HOME", str(tmp_path))
    log_path = str(tmp_path / "audit.log")
    append_record(log_path, "encode", ok=True)
    append_record(log_path, "decode", ok=True)
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec = json.loads(lines[-1])
    rec["prev"] = "ff" * 32
    lines[-1] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    intact, _, bad = verify_chain(log_path)
    assert intact is False
    assert bad == 2


@pytest.mark.security
def test_zero_byte_payload_rejected():
    from stegx.utils import create_payload_from_bytes
    with pytest.raises(EmptyPayloadError):
        create_payload_from_bytes("empty.bin", b"")


@pytest.mark.security
def test_fips_assert_rejects_non_fips_backend(monkeypatch):
    from stegx import fips


    monkeypatch.setattr(fips, "_fips_active", False, raising=False)
    with pytest.raises(FipsPolicyViolation):
        fips.assert_fips_runtime()


@pytest.mark.security
def test_panic_atomic_replace_retries_and_raises(monkeypatch, tmp_path):
    from stegx import panic as panic_mod

    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_bytes(b"new")
    dst.write_bytes(b"old")

    calls = {"n": 0}

    def always_permission_error(_a, _b):
        calls["n"] += 1
        raise PermissionError("held by AV")

    monkeypatch.setattr(panic_mod.os, "replace", always_permission_error)

    monkeypatch.setattr(panic_mod, "_REPLACE_SLEEP_S", 0.001)

    with pytest.raises(PanicReplaceFailed):
        panic_mod._atomic_replace(str(src), str(dst))
    assert calls["n"] >= panic_mod._REPLACE_RETRIES
