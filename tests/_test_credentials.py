from __future__ import annotations

import hashlib


_TEST_SEED = b"stegx-test-corpus-v3"

def derive_password(label: str, *, length: int = 40) -> str:
    if not isinstance(label, str) or not label:
        raise ValueError("label must be a non-empty string")
    if length < 16 or length > 64:
        raise ValueError("length must be in [16, 64]")
    digest = hashlib.sha256(_TEST_SEED + label.encode("utf-8")).hexdigest()
    return digest[:length]
