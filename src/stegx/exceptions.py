from __future__ import annotations

from cryptography.exceptions import InvalidTag

class StegXError(Exception):
    pass

class AuthenticationFailure(StegXError, InvalidTag):
    pass

class InsufficientCapacity(StegXError, ValueError):
    pass

class CorruptedPayload(StegXError, ValueError):
    pass

class UnsupportedImageMode(StegXError, ValueError):
    pass

class PanicDestructionFailed(StegXError, OSError):
    pass

class DecompressionBombError(StegXError, ValueError):
    pass

class TarExtractionError(StegXError, ValueError):
    pass

class LegacyFormatRejected(StegXError, ValueError):
    pass

class FipsPolicyViolation(StegXError, RuntimeError):
    pass

class HeaderParameterOutOfRange(StegXError, ValueError):
    pass

class KmsUnwrapFailure(StegXError, RuntimeError):
    pass

class YubikeyReplayDetected(StegXError, RuntimeError):
    pass

class EmptyPayloadError(StegXError, ValueError):
    pass

class InsufficientSharesError(StegXError, ValueError):
    pass

class PanicReplaceFailed(StegXError, OSError):
    pass
