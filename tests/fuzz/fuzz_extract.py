from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import zlib


_HERE = os.path.dirname(os.path.abspath(__file__))
_STEGX_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _STEGX_ROOT not in sys.path:
    sys.path.insert(0, _STEGX_ROOT)

FUZZ_PASSWORD = "fuzz-test-password-12345"

def _fuzz_extract(data: bytes) -> None:
    from cryptography.exceptions import InvalidTag

    from stegx.steganography import extract_v2


    fd = None
    try:
        fd = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        fd.write(data)
        fd.close()

        try:
            extract_v2(fd.name, FUZZ_PASSWORD)
        except (
            ValueError,
            OSError,
            InvalidTag,
            FileNotFoundError,
            RuntimeError,
            KeyError,
            IndexError,
            struct.error,
            zlib.error,
            OverflowError,
            MemoryError,
        ):

            pass
    finally:
        if fd is not None:
            try:
                os.unlink(fd.name)
            except OSError:
                pass

def main() -> None:
    try:
        import atheris
    except ImportError:
        print(
            "atheris not installed. Install with: pip install atheris\n"
            "Running a quick smoke test with random bytes instead.",
            file=sys.stderr,
        )
        for _ in range(100):
            _fuzz_extract(os.urandom(256))
        print("Smoke test passed (100 random inputs).", file=sys.stderr)
        return

    atheris.Setup(sys.argv, _fuzz_extract)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
