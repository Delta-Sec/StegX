from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Callable, Optional

from .fips import ban_if_fips

_LOG = logging.getLogger(__name__)

try:
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.yubiotp import SLOT, YubiOtpSession
    from ykman.device import list_all_devices

    YUBIKEY_AVAILABLE = True
except ImportError:
    YUBIKEY_AVAILABLE = False

YUBIKEY_RESPONSE_LEN = 20

def challenge_for_operation(nonce: bytes, fingerprint: bytes) -> bytes:
    if len(nonce) < 16:
        raise ValueError("nonce must be at least 16 bytes")
    return hashlib.sha256(
        b"stegx/v3/yk-challenge\x00" + nonce + fingerprint
    ).digest()

class YubiKeyError(RuntimeError):
    pass

class YubiKeyBackend:

    def challenge_response(self, challenge: bytes, slot: int = 2) -> bytes:
        raise NotImplementedError

class HardwareYubiKey(YubiKeyBackend):
    def challenge_response(self, challenge: bytes, slot: int = 2) -> bytes:
        if not YUBIKEY_AVAILABLE:
            raise YubiKeyError(
                "ykman / yubikit are not installed. `pip install ykman` to enable."
            )
        devices = list_all_devices()
        if not devices:
            raise YubiKeyError("No YubiKey detected.")

        dev, info = devices[0]
        _LOG.info("Querying YubiKey serial=%s on slot %d (touch if required)",
                  info.serial, slot)
        try:
            with dev.open_connection(SmartCardConnection) as conn:
                session = YubiOtpSession(conn)
                slot_id = SLOT.TWO if slot == 2 else SLOT.ONE
                response = session.calculate_hmac_sha1(slot_id, challenge, event=None)
        except Exception as e:
            raise YubiKeyError(f"YubiKey challenge-response failed: {e}")
        if len(response) != YUBIKEY_RESPONSE_LEN:
            raise YubiKeyError(
                f"Unexpected YubiKey response length: {len(response)} "
                f"(expected {YUBIKEY_RESPONSE_LEN})"
            )
        return bytes(response)

class MockYubiKey(YubiKeyBackend):
    def __init__(self, secret: bytes = b"stegx-test-mock-yubikey-secret"):
        if not secret:
            raise ValueError("Mock YubiKey secret must be non-empty.")
        self._secret = bytes(secret)

    def challenge_response(self, challenge: bytes, slot: int = 2) -> bytes:
        if not challenge:
            raise ValueError("Challenge must be non-empty.")
        return hmac.new(self._secret, challenge, hashlib.sha1).digest()

def resolve_yubikey_response(
    challenge: bytes,
    backend: Optional[YubiKeyBackend] = None,
    *,
    response_file: Optional[str] = None,
    response_override: Optional[bytes] = None,
    factory: Optional[Callable[[], YubiKeyBackend]] = None,
) -> bytes:
    ban_if_fips("YubiKey HMAC-SHA1 challenge-response")
    if response_override is not None:
        return _validate_response(response_override)
    if response_file:
        with open(response_file, "rb") as f:
            raw = f.read().strip()
        if len(raw) == 2 * YUBIKEY_RESPONSE_LEN:
            raw = bytes.fromhex(raw.decode("ascii"))
        return _validate_response(raw)
    if backend is None and factory is not None:
        backend = factory()
    if backend is None:
        backend = HardwareYubiKey()
    return _validate_response(backend.challenge_response(challenge))

def _validate_response(resp: bytes) -> bytes:
    if not isinstance(resp, (bytes, bytearray)):
        raise TypeError("YubiKey response must be bytes-like.")
    if len(resp) != YUBIKEY_RESPONSE_LEN:
        raise YubiKeyError(
            f"YubiKey response must be {YUBIKEY_RESPONSE_LEN} bytes, got {len(resp)}."
        )
    return bytes(resp)
