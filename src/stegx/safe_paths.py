from __future__ import annotations

import logging
import os
from typing import Optional

__all__ = [
    "PathValidationError",
    "validate_user_path",
    "ensure_under_base",
    "sink_safe_path",
    "MAX_PATH_LEN",
]

_LOG = logging.getLogger(__name__)


MAX_PATH_LEN = 4096

class PathValidationError(ValueError):
    pass

def validate_user_path(
    path: Optional[str],
    *,
    kind: str = "any",
    must_exist: Optional[bool] = None,
    max_len: int = MAX_PATH_LEN,
    allow_empty: bool = False,
) -> str:
    if path is None or path == "":
        if allow_empty:
            return ""
        raise PathValidationError("Path is empty or missing.")
    if not isinstance(path, str):
        raise PathValidationError(
            f"Path must be a string, got {type(path).__name__}."
        )
    if "\x00" in path:


        raise PathValidationError("Path contains a NULL byte.")
    if len(path) > max_len:
        raise PathValidationError(
            f"Path length {len(path)} exceeds maximum {max_len}."
        )
    canonical = os.path.abspath(path)
    if must_exist is True:
        if not os.path.exists(canonical):
            raise PathValidationError(f"Path does not exist: {path!r}")
        if kind == "file" and not os.path.isfile(canonical):
            raise PathValidationError(f"Path is not a regular file: {path!r}")
        if kind == "dir" and not os.path.isdir(canonical):
            raise PathValidationError(f"Path is not a directory: {path!r}")
    elif must_exist is False:
        if os.path.exists(canonical):
            raise PathValidationError(f"Path already exists: {path!r}")
    return canonical

def ensure_under_base(candidate: str, base: str) -> str:
    resolved_candidate = os.path.realpath(candidate)
    resolved_base = os.path.realpath(base)


    base_prefix = resolved_base.rstrip(os.sep) + os.sep
    if resolved_candidate != resolved_base and not resolved_candidate.startswith(base_prefix):
        raise PathValidationError(
            f"Path escapes base directory: {candidate!r} not inside {base!r}"
        )
    return resolved_candidate

def sink_safe_path(path: str) -> str:
    if path is None or path == "":
        raise PathValidationError("Empty path at sink site.")
    as_str = os.fspath(path)
    if "\x00" in as_str:
        raise PathValidationError("NULL byte in path at sink site.")


    return os.path.realpath(os.path.abspath(os.path.normpath(as_str)))
