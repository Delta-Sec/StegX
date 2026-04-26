
import os
import random

import pytest

from stegx.exceptions import InsufficientSharesError
from stegx.shamir import combine_shares, split_secret

def test_split_combine_basic():
    secret = b"The secret value is 42."
    shares = split_secret(secret, k=3, n=5)
    assert len(shares) == 5
    assert all(len(s) == len(secret) + 2 for s in shares)

    assert combine_shares(shares) == secret

    assert combine_shares(shares[:3]) == secret

    assert combine_shares([shares[0], shares[2], shares[4]]) == secret

def test_fewer_than_threshold_does_not_recover():
    secret = bytes(range(32))
    shares = split_secret(secret, k=4, n=6)
    with pytest.raises(InsufficientSharesError):
        combine_shares(shares[:2])

    assert combine_shares(shares[:4]) == secret

def test_identical_x_coords_rejected():
    secret = b"hi"
    shares = split_secret(secret, k=2, n=3)
    with pytest.raises(ValueError):
        combine_shares([shares[0], shares[0]])

def test_invalid_parameters():
    with pytest.raises(ValueError):
        split_secret(b"", k=2, n=3)
    with pytest.raises(ValueError):
        split_secret(b"abc", k=0, n=3)
    with pytest.raises(ValueError):
        split_secret(b"abc", k=4, n=3)
    with pytest.raises(ValueError):
        split_secret(b"abc", k=2, n=256)

@pytest.mark.parametrize("size", [1, 16, 32, 4096])
def test_roundtrip_random_sizes(size):
    secret = os.urandom(size)
    shares = split_secret(secret, k=3, n=5)
    picked = random.sample(shares, 3)
    assert combine_shares(picked) == secret
