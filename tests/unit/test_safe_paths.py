from __future__ import annotations

import os

import pytest

from stegx.safe_paths import (
    MAX_PATH_LEN,
    PathValidationError,
    ensure_under_base,
    sink_safe_path,
    validate_user_path,
)


def test_validate_rejects_none():
    with pytest.raises(PathValidationError):
        validate_user_path(None)

def test_validate_rejects_empty_string():
    with pytest.raises(PathValidationError):
        validate_user_path("")

def test_validate_allows_empty_when_opted_in():
    assert validate_user_path("", allow_empty=True) == ""
    assert validate_user_path(None, allow_empty=True) == ""

def test_validate_rejects_null_byte(tmp_path):


    bad = f"{tmp_path}/foo\x00bar.txt"
    with pytest.raises(PathValidationError, match="NULL byte"):
        validate_user_path(bad)

def test_validate_rejects_oversize_path():
    huge = "a" * (MAX_PATH_LEN + 1)
    with pytest.raises(PathValidationError, match="length"):
        validate_user_path(huge)

def test_validate_rejects_non_string():
    with pytest.raises(PathValidationError):
        validate_user_path(12345)

def test_validate_returns_absolute_path(tmp_path):

    rel = "foo/bar"
    resolved = validate_user_path(rel)
    assert os.path.isabs(resolved)

def test_validate_must_exist_true_rejects_missing(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(PathValidationError, match="does not exist"):
        validate_user_path(str(missing), must_exist=True)

def test_validate_must_exist_true_accepts_existing_file(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    assert validate_user_path(str(f), must_exist=True) == str(f.resolve())

def test_validate_kind_file_rejects_directory(tmp_path):
    with pytest.raises(PathValidationError, match="not a regular file"):
        validate_user_path(str(tmp_path), kind="file", must_exist=True)

def test_validate_kind_dir_rejects_file(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    with pytest.raises(PathValidationError, match="not a directory"):
        validate_user_path(str(f), kind="dir", must_exist=True)

def test_validate_must_exist_false_rejects_existing(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    with pytest.raises(PathValidationError, match="already exists"):
        validate_user_path(str(f), must_exist=False)


def test_ensure_under_base_accepts_nested(tmp_path):
    base = tmp_path
    candidate = tmp_path / "sub" / "file.dat"
    candidate.parent.mkdir()
    candidate.write_bytes(b"ok")
    resolved = ensure_under_base(str(candidate), str(base))
    assert resolved.startswith(str(base.resolve()))

def test_ensure_under_base_rejects_traversal(tmp_path):
    base = tmp_path / "inside"
    base.mkdir()
    escape = tmp_path / "outside.txt"
    with pytest.raises(PathValidationError, match="escapes base"):
        ensure_under_base(str(escape), str(base))

def test_ensure_under_base_rejects_sibling_prefix(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    sibling = tmp_path / "outside"
    sibling.mkdir()
    with pytest.raises(PathValidationError, match="escapes base"):
        ensure_under_base(str(sibling), str(base))

def test_ensure_under_base_accepts_base_itself(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    resolved = ensure_under_base(str(base), str(base))
    assert resolved == str(base.resolve())


def test_sink_safe_path_rejects_none():
    with pytest.raises(PathValidationError, match="Empty path"):
        sink_safe_path(None)

def test_sink_safe_path_rejects_empty():
    with pytest.raises(PathValidationError, match="Empty path"):
        sink_safe_path("")

def test_sink_safe_path_rejects_null_byte(tmp_path):
    with pytest.raises(PathValidationError, match="NULL byte"):
        sink_safe_path(f"{tmp_path}/a\x00b.txt")

def test_sink_safe_path_accepts_pathlike(tmp_path):
    resolved = sink_safe_path(tmp_path)
    assert os.path.isabs(resolved)

    assert resolved == os.path.realpath(str(tmp_path))

def test_sink_safe_path_canonicalises_relative(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    resolved = sink_safe_path("x.bin")
    assert os.path.isabs(resolved)
    assert resolved == os.path.realpath(str(f))

def test_sink_safe_path_is_idempotent(tmp_path):
    once = sink_safe_path(str(tmp_path))
    twice = sink_safe_path(once)
    assert once == twice

def test_sink_safe_path_collapses_dotdot(tmp_path):
    weird = os.path.join(str(tmp_path), "sub", "..", "x.bin")
    resolved = sink_safe_path(weird)
    assert ".." not in resolved.split(os.sep)

def test_sink_safe_path_is_a_str():
    result = sink_safe_path(__file__)
    assert isinstance(result, str)
