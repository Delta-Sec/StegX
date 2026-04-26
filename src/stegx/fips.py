from __future__ import annotations

import logging
from typing import Optional

from .exceptions import FipsPolicyViolation

_LOG = logging.getLogger(__name__)

_fips_active: bool = False

def is_fips_active() -> bool:
    return _fips_active

def _backend_fips_flag() -> Optional[bool]:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
    except ImportError:
        backend = None
    flag = _probe_fips_enabled(backend)
    if flag is not None:
        return flag


    try:
        from cryptography.hazmat.backends import default_backend
        alt_backend = default_backend()
    except ImportError:
        return None
    except Exception:
        return None
    return _probe_fips_enabled(alt_backend)

def _probe_fips_enabled(backend_obj: object) -> Optional[bool]:
    if backend_obj is None:
        return None
    getter = getattr(backend_obj, "_fips_enabled", None)
    if getter is None:
        return None
    if callable(getter):
        try:
            return bool(getter())
        except Exception:
            return None


    if isinstance(getter, bool):
        return getter
    return None

def assert_fips_runtime() -> None:
    global _fips_active
    flag = _backend_fips_flag()
    if flag is not True:
        raise FipsPolicyViolation(
            "--fips requires the cryptography library to be linked against "
            "a FIPS 140-validated OpenSSL build with FIPS mode enabled. "
            "The current backend does not report FIPS mode active, so the "
            "claim cannot be satisfied. Remove --fips to run the normal "
            "non-FIPS pipeline, or rebuild against a validated OpenSSL."
        )
    _fips_active = True
    _LOG.info("FIPS policy asserted — PBKDF2 / AES-GCM / zlib only.")

def ban_if_fips(kind: str) -> None:
    if not _fips_active:
        return
    raise FipsPolicyViolation(
        f"--fips forbids {kind}: primitive is not on the FIPS 140 "
        "validated algorithm list."
    )
