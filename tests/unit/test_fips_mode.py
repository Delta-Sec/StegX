
import argparse

import pytest

from stegx import _apply_fips_policy
from stegx.exceptions import FipsPolicyViolation

@pytest.fixture(autouse=True)
def _fake_fips_runtime(monkeypatch):
    monkeypatch.setattr("stegx.fips.assert_fips_runtime", lambda: None)

def _base_args(**overrides):
    ns = argparse.Namespace(
        fips=True,
        kdf="argon2id",
        dual_cipher=False,
        compression="best",
        yubikey=False,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns

def test_fips_forces_pbkdf2():
    a = _base_args()
    _apply_fips_policy(a)
    assert a.kdf == "pbkdf2"

def test_fips_preserves_pbkdf2_when_already_selected():
    a = _base_args(kdf="pbkdf2")
    _apply_fips_policy(a)
    assert a.kdf == "pbkdf2"

def test_fips_forces_compression_fast():
    a = _base_args(compression="best")
    _apply_fips_policy(a)
    assert a.compression == "fast"

def test_fips_rejects_dual_cipher():
    a = _base_args(dual_cipher=True)
    with pytest.raises(ValueError, match="FIPS"):
        _apply_fips_policy(a)

def test_fips_rejects_yubikey():
    a = _base_args(yubikey=True)
    with pytest.raises(ValueError, match="FIPS"):
        _apply_fips_policy(a)

def test_fips_noop_when_flag_absent():
    a = argparse.Namespace(
        fips=False, kdf="argon2id", dual_cipher=True, compression="best",
        yubikey=True,
    )
    _apply_fips_policy(a)

    assert a.kdf == "argon2id"
    assert a.compression == "best"
    assert a.dual_cipher is True

def test_fips_runtime_check_rejects_non_fips_backend():
    import importlib
    import stegx.fips as fips_mod

    importlib.reload(fips_mod)
    try:
        a = _base_args()
        with pytest.raises(FipsPolicyViolation):
            _apply_fips_policy(a)
    finally:
        importlib.reload(fips_mod)
