from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import stat
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

_LOG = logging.getLogger(__name__)

_GENESIS_PREV = ""

_AUDIT_KEY_FILENAME = "audit.key"
_AUDIT_KEY_LEN = 32

def _audit_dir() -> str:
    env = os.environ.get("STEGX_CONFIG_HOME")
    if env:
        if "\x00" in env:
            raise ValueError(
                "STEGX_CONFIG_HOME contains a NULL byte; refusing to use."
            )
        return os.path.abspath(env)
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "StegX")
    return os.path.join(os.path.expanduser("~"), ".config", "stegx")

def resolve_or_create_audit_key() -> bytes:
    cfg = _audit_dir()


    from .safe_paths import sink_safe_path, validate_user_path

    key_path = validate_user_path(
        os.path.join(cfg, _AUDIT_KEY_FILENAME),
    )


    read_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        read_flags |= os.O_BINARY
    try:
        rfd = os.open(key_path, read_flags)
    except (FileNotFoundError, OSError):
        rfd = None
    if rfd is not None:
        try:
            st = os.fstat(rfd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(
                    f"audit key at {key_path} is not a regular file; refusing to load."
                )


            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise OSError(
                    f"audit key at {key_path} is owned by another user; refusing to load."
                )
            data = b""
            while True:
                chunk = os.read(rfd, 4096)
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(rfd)
        if len(data) >= _AUDIT_KEY_LEN:
            return data[:_AUDIT_KEY_LEN]
        _LOG.warning("audit key at %s is short; regenerating", key_path)
    os.makedirs(cfg, exist_ok=True)
    key = os.urandom(_AUDIT_KEY_LEN)


    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        write_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        write_flags |= os.O_BINARY
    try:
        fd = os.open(key_path, write_flags, 0o600)
    except FileExistsError:


        try:


            os.unlink(sink_safe_path(key_path))
        except OSError:
            pass
        fd = os.open(key_path, write_flags, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    try:


        os.chmod(sink_safe_path(key_path), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key

def _canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def _file_sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        _LOG.debug("audit: could not hash %s: %s", path, e)
        return None

def _last_chain_hash(log_path: str) -> str:
    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        return _GENESIS_PREV
    last = ""
    try:
        with open(log_path, "rb") as f:

            f.seek(0, os.SEEK_END)
            size = f.tell()
            back = min(size, 16384)
            f.seek(size - back)
            tail = f.read().decode("utf-8", errors="replace")
            lines = [line for line in tail.splitlines() if line.strip()]
            if not lines:
                return _GENESIS_PREV
            last = lines[-1]
    except OSError as e:
        _LOG.debug("audit: failed reading tail of %s: %s", log_path, e)
        return _GENESIS_PREV
    try:
        record = json.loads(last)
        return str(record.get("chain") or _GENESIS_PREV)
    except json.JSONDecodeError:
        return _GENESIS_PREV

def append_record(
    log_path: str,
    op: str,
    *,
    ok: bool,
    cover_path: Optional[str] = None,
    stego_path: Optional[str] = None,
    flags: Optional[Iterable[str]] = None,
    note: Optional[str] = None,
    hmac_key: Optional[bytes] = None,
    allow_unauthenticated: bool = False,
) -> bool:
    if hmac_key is None and not allow_unauthenticated:
        try:
            hmac_key = resolve_or_create_audit_key()
        except OSError as key_err:
            _LOG.warning(
                "audit: could not resolve machine-local HMAC key (%s); "
                "refusing to write an unauthenticated record. Pass "
                "allow_unauthenticated=True to override.",
                key_err,
            )
            return False
    try:
        prev = _last_chain_hash(log_path)
        record: Dict[str, Any] = {
            "ts": _now_iso(),
            "op": op,
            "ok": bool(ok),
            "cover": _file_sha256(cover_path) if cover_path else None,
            "stego": _file_sha256(stego_path) if stego_path else None,
            "flags": sorted(flags) if flags else [],
            "note": note,
            "prev": prev,
        }


        chain = hashlib.sha256(_canonical_json(record)).hexdigest()
        record["chain"] = chain

        if hmac_key:


            record["hmac"] = hmac.new(
                hmac_key, _canonical_json(record), hashlib.sha256
            ).hexdigest()

        os.makedirs(os.path.dirname(os.path.abspath(log_path)) or ".", exist_ok=True)
        with open(log_path, "ab") as f:
            f.write(_canonical_json(record))
            f.write(b"\n")
        return True
    except OSError as e:
        _LOG.warning("audit: could not append to %s: %s", log_path, e)
        return False

def verify_chain(
    log_path: str,
    *,
    hmac_key: Optional[bytes] = None,
) -> Tuple[bool, int, Optional[int]]:
    if not os.path.exists(log_path):
        return True, 0, None
    prev = _GENESIS_PREV
    count = 0
    with open(log_path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, count, lineno
            count += 1
            claimed_hmac = record.get("hmac")
            claimed_chain = record.get("chain")
            if record.get("prev") != prev:
                return False, count, lineno


            chain_input = {k: v for k, v in record.items() if k not in ("hmac", "chain")}
            expected_chain = hashlib.sha256(_canonical_json(chain_input)).hexdigest()
            if claimed_chain != expected_chain:
                return False, count, lineno
            if hmac_key is not None:
                if claimed_hmac is None:
                    return False, count, lineno
                hmac_input = {k: v for k, v in record.items() if k != "hmac"}
                expected_hmac = hmac.new(
                    hmac_key, _canonical_json(hmac_input), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(claimed_hmac, expected_hmac):
                    return False, count, lineno
            prev = str(claimed_chain)
    return True, count, None

def summarise(log_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(log_path):
        return []
    out: List[Dict[str, Any]] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
