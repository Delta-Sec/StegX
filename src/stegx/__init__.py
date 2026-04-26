from __future__ import annotations


import getpass
import os
import sys

try:
    from stegx._version import version as __version__
except ImportError:
    try:
        from importlib.metadata import version as _pkg_version
        __version__ = _pkg_version("stegx")
    except Exception:
        __version__ = "0.0.0+unknown"


from stegx.exceptions import StegXError
from stegx.shamir import combine_shares, split_secret
from stegx.steganography import (
    EmbedOptions,
    embed_v2 as embed,
    extract_v2 as extract,
)


from stegx.cli import (
    _apply_fips_policy,
    _build_version_string,
    main,
    perform_decode,
    perform_encode,
    perform_pick_cover,
    perform_rewrap,
    perform_shamir_combine,
    perform_shamir_split,
)

__all__ = [

    "__version__",

    "embed",
    "extract",
    "EmbedOptions",
    "split_secret",
    "combine_shares",
    "StegXError",

    "main",
    "perform_encode",
    "perform_decode",
    "perform_rewrap",
    "perform_shamir_split",
    "perform_shamir_combine",
    "perform_pick_cover",
    "_apply_fips_policy",
    "_build_version_string",
]
