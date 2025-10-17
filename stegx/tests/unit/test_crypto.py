#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for StegX crypto module."""

import os
import pytest
from cryptography.exceptions import InvalidTag

# Import the module to test
from stegx_core.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    SALT_SIZE,
    NONCE_SIZE,
    KEY_SIZE
)

# Test fixtures
@pytest.fixture
def sample_data():
    """Generate sample data for testing."""
    return b"StegX test data for encryption and decryption 1234567890!@#$%^&*()"

@pytest.fixture
def sample_password():
    """Generate sample password for testing."""
    return "StegXTestPassword123!@#"

# Tests for derive_key
def test_derive_key():
    """Test key derivation from password and salt."""
    # Test with fixed password and salt for deterministic result
    password = "test_password"
    salt = b"0123456789abcdef"  # 16 bytes
    
    # Derive key
    key = derive_key(password, salt)
    
    # Verify key properties
    assert isinstance(key, bytes)
    assert len(key) == KEY_SIZE  # Should be 32 bytes for AES-256
    
    # Verify deterministic behavior (same password + salt = same key)
    key2 = derive_key(password, salt)
    assert key == key2
    
    # Verify different salt produces different key
    different_salt = b"fedcba9876543210"  # 16 bytes
    different_key = derive_key(password, different_salt)
    assert key != different_key
    
    # Verify different password produces different key
    different_password = "different_password"
    different_key = derive_key(different_password, salt)
    assert key != different_key
    
    # Test with bytes password
    bytes_password = b"bytes_password"
    bytes_key = derive_key(bytes_password, salt)
    assert isinstance(bytes_key, bytes)
    assert len(bytes_key) == KEY_SIZE

# Tests for encrypt_data
def test_encrypt_data(sample_data, sample_password):
    """Test data encryption."""
    # Encrypt data
    encrypted = encrypt_data(sample_data, sample_password)
    
    # Verify encrypted data properties
    assert isinstance(encrypted, bytes)
    assert len(encrypted) > len(sample_data)  # Encrypted data should be larger (salt + nonce + ciphertext + tag)
    
    # Verify structure: salt (16 bytes) + nonce (12 bytes) + ciphertext + tag
    assert len(encrypted) >= SALT_SIZE + NONCE_SIZE + len(sample_data)
    
    # Verify different calls produce different results (due to random salt and nonce)
    encrypted2 = encrypt_data(sample_data, sample_password)
    assert encrypted != encrypted2
    
    # Extract salt and nonce from both encryptions
    salt1 = encrypted[:SALT_SIZE]
    salt2 = encrypted2[:SALT_SIZE]
    nonce1 = encrypted[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    nonce2 = encrypted2[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    
    # Verify salt and nonce are different between calls
    assert salt1 != salt2
    assert nonce1 != nonce2

def test_encrypt_data_input_validation():
    """Test input validation for encrypt_data."""
    valid_data = b"test data"
    valid_password = "test password"
    
    # Test with non-bytes data
    with pytest.raises(TypeError):
        encrypt_data("string data", valid_password)
    
    # Test with non-string password
    with pytest.raises(TypeError):
        encrypt_data(valid_data, b"bytes password")
    
    # Test with empty password
    with pytest.raises(ValueError):
        encrypt_data(valid_data, "")

# Tests for decrypt_data
def test_decrypt_data(sample_data, sample_password):
    """Test data decryption."""
    # Encrypt data first
    encrypted = encrypt_data(sample_data, sample_password)
    
    # Decrypt data
    decrypted = decrypt_data(encrypted, sample_password)
    
    # Verify decrypted data matches original
    assert decrypted == sample_data

def test_decrypt_data_wrong_password(sample_data, sample_password):
    """Test decryption with wrong password."""
    # Encrypt data
    encrypted = encrypt_data(sample_data, sample_password)
    
    # Attempt to decrypt with wrong password
    wrong_password = sample_password + "wrong"
    with pytest.raises(InvalidTag):
        decrypt_data(encrypted, wrong_password)

def test_decrypt_data_corrupted(sample_data, sample_password):
    """Test decryption with corrupted data."""
    # Encrypt data
    encrypted = encrypt_data(sample_data, sample_password)
    
    # Corrupt the ciphertext portion (after salt and nonce)
    header_size = SALT_SIZE + NONCE_SIZE
    corrupted = encrypted[:header_size] + bytes([encrypted[header_size] ^ 0x01]) + encrypted[header_size + 1:]
    
    # Attempt to decrypt corrupted data
    with pytest.raises(InvalidTag):
        decrypt_data(corrupted, sample_password)

def test_decrypt_data_input_validation():
    """Test input validation for decrypt_data."""
    # Create valid encrypted data
    valid_data = encrypt_data(b"test data", "test password")
    valid_password = "test password"
    
    # Test with non-bytes encrypted data
    with pytest.raises(TypeError):
        decrypt_data("string data", valid_password)
    
    # Test with non-string password
    with pytest.raises(TypeError):
        decrypt_data(valid_data, b"bytes password")
    
    # Test with empty password
    with pytest.raises(ValueError):
        decrypt_data(valid_data, "")
    
    # Test with too short encrypted data
    with pytest.raises(ValueError):
        decrypt_data(b"too short", valid_password)

# Tests for encrypt-decrypt cycle with different data types
@pytest.mark.parametrize("test_data", [
    b"",  # Empty data
    b"a",  # Single byte
    b"StegX" * 1000,  # Larger data
    bytes([i % 256 for i in range(1000)])  # Binary data with all byte values
])
def test_encrypt_decrypt_cycle(test_data, sample_password):
    """Test encrypt-decrypt cycle with different data types."""
    encrypted = encrypt_data(test_data, sample_password)
    decrypted = decrypt_data(encrypted, sample_password)
    assert decrypted == test_data

if __name__ == "__main__":
    pytest.main(["-v", __file__])
