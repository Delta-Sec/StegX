#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for StegX steganography module."""

import os
import pytest
from PIL import Image
import tempfile
import numpy as np
from pathlib import Path

# Import the module to test
from stegx_core.steganography import (
    bytes_to_bits_iterator,
    bits_to_bytes,
    calculate_lsb_capacity,
    embed_data,
    extract_data,
    DATA_SENTINEL,
    SENTINEL_BITS,
    SENTINEL_LENGTH_BITS
)

# Test fixtures
@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname

@pytest.fixture
def sample_data():
    """Generate sample data for testing."""
    return b"StegX test data 1234567890!@#$%^&*()"

@pytest.fixture
def create_test_image(temp_dir):
    """Create test images with different modes and sizes."""
    def _create_image(width, height, mode="RGB", filename=None):
        if filename is None:
            filename = f"test_{mode}_{width}x{height}.png"
        
        filepath = os.path.join(temp_dir, filename)
        
        if mode == "RGB":
            # Create RGB image
            img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            img = Image.fromarray(img_array, mode)
        elif mode == "RGBA":
            # Create RGBA image
            img_array = np.random.randint(0, 256, (height, width, 4), dtype=np.uint8)
            img = Image.fromarray(img_array, mode)
        elif mode == "L":
            # Create grayscale image
            img_array = np.random.randint(0, 256, (height, width), dtype=np.uint8)
            img = Image.fromarray(img_array, mode)
        elif mode == "P":
            # Create palette image (will be converted during tests)
            img = Image.new("P", (width, height), color=0)
            # Fill with some pattern
            for y in range(height):
                for x in range(width):
                    img.putpixel((x, y), (x + y) % 256)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        
        img.save(filepath)
        return filepath
    
    return _create_image

# Tests for bytes_to_bits_iterator
def test_bytes_to_bits_iterator():
    """Test conversion from bytes to bits."""
    # Test with a simple byte
    test_byte = bytes([0b10101010])
    bits = list(bytes_to_bits_iterator(test_byte))
    assert bits == [1, 0, 1, 0, 1, 0, 1, 0]
    
    # Test with multiple bytes
    test_bytes = bytes([0b11001100, 0b10101010])
    bits = list(bytes_to_bits_iterator(test_bytes))
    assert bits == [1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0]
    
    # Test with empty bytes
    assert list(bytes_to_bits_iterator(b"")) == []

# Tests for bits_to_bytes
def test_bits_to_bytes():
    """Test conversion from bits to bytes."""
    # Test with a simple byte
    bits = [1, 0, 1, 0, 1, 0, 1, 0]
    result = bits_to_bytes(bits)
    assert result == bytes([0b10101010])
    
    # Test with multiple bytes
    bits = [1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0]
    result = bits_to_bytes(bits)
    assert result == bytes([0b11001100, 0b10101010])
    
    # Test with string bits
    bits = "10101010"
    result = bits_to_bytes(bits)
    assert result == bytes([0b10101010])
    
    # Test with empty bits
    assert bits_to_bytes([]) == b""
    
    # Test with non-binary values
    with pytest.raises(ValueError):
        bits_to_bytes([1, 2, 3])

# Tests for calculate_lsb_capacity
def test_calculate_lsb_capacity(create_test_image):
    """Test calculation of LSB capacity for different image types."""
    # Test RGB image
    rgb_path = create_test_image(100, 100, "RGB")
    with Image.open(rgb_path) as img:
        capacity = calculate_lsb_capacity(img)
        # 100x100 RGB image should have 100*100*3 - SENTINEL_LENGTH_BITS bits capacity
        assert capacity == 100 * 100 * 3 - SENTINEL_LENGTH_BITS
    
    # Test grayscale image
    gray_path = create_test_image(100, 100, "L")
    with Image.open(gray_path) as img:
        capacity = calculate_lsb_capacity(img)
        # 100x100 grayscale image should have 100*100 - SENTINEL_LENGTH_BITS bits capacity
        assert capacity == 100 * 100 - SENTINEL_LENGTH_BITS
    
    # Test unsupported mode (should raise ValueError)
    with pytest.raises(ValueError):
        # Create a mock image with unsupported mode
        img = Image.new("CMYK", (100, 100))
        calculate_lsb_capacity(img)

# Tests for embed_data and extract_data
def test_embed_and_extract_data(create_test_image, sample_data, temp_dir):
    """Test embedding and extracting data in images."""
    # Test with RGB image
    cover_path = create_test_image(100, 100, "RGB")
    output_path = os.path.join(temp_dir, "stego_rgb.png")
    
    # Embed data
    embed_data(cover_path, sample_data, output_path)
    
    # Verify output file exists
    assert os.path.exists(output_path)
    
    # Extract data
    extracted_data = extract_data(output_path)
    
    # Verify extracted data matches original
    assert extracted_data == sample_data
    
    # Test with grayscale image
    cover_path = create_test_image(100, 100, "L")
    output_path = os.path.join(temp_dir, "stego_gray.png")
    
    # Embed data
    embed_data(cover_path, sample_data, output_path)
    
    # Extract data
    extracted_data = extract_data(output_path)
    
    # Verify extracted data matches original
    assert extracted_data == sample_data

def test_embed_data_capacity_error(create_test_image, temp_dir):
    """Test embedding data that exceeds image capacity."""
    # Create a very small image
    cover_path = create_test_image(10, 10, "L")
    output_path = os.path.join(temp_dir, "stego_small.png")
    
    # Create data larger than capacity
    # 10x10 grayscale = 100 bits - sentinel bits
    # We'll create data that's definitely larger
    large_data = b"X" * 100  # 800 bits
    
    # Attempt to embed should raise ValueError
    with pytest.raises(ValueError) as excinfo:
        embed_data(cover_path, large_data, output_path)
    
    # Verify error message mentions capacity
    assert "capacity" in str(excinfo.value).lower()

def test_extract_data_no_sentinel(create_test_image, temp_dir):
    """Test extracting data from an image with no hidden data."""
    # Create a regular image with no hidden data
    cover_path = create_test_image(50, 50, "RGB")
    
    # Attempt to extract should raise ValueError
    with pytest.raises(ValueError) as excinfo:
        extract_data(cover_path)
    
    # Verify error message mentions sentinel
    assert "sentinel" in str(excinfo.value).lower()

def test_file_not_found_errors():
    """Test file not found errors are properly raised."""
    # Test with non-existent cover image
    with pytest.raises(FileNotFoundError):
        embed_data("non_existent_image.png", b"test", "output.png")
    
    # Test with non-existent stego image
    with pytest.raises(FileNotFoundError):
        extract_data("non_existent_image.png")

def test_palette_image_conversion(create_test_image, sample_data, temp_dir):
    """Test automatic conversion of palette images."""
    # Create a palette image
    cover_path = create_test_image(50, 50, "P")
    output_path = os.path.join(temp_dir, "stego_palette.png")
    
    # Embed data (should automatically convert to RGB/RGBA)
    embed_data(cover_path, sample_data, output_path)
    
    # Extract data
    extracted_data = extract_data(output_path)
    
    # Verify extracted data matches original
    assert extracted_data == sample_data
    
    # Verify output image is no longer in palette mode
    with Image.open(output_path) as img:
        assert img.mode != "P"

# Additional tests for edge cases and error handling
def test_empty_data(create_test_image, temp_dir):
    """Test embedding and extracting empty data."""
    cover_path = create_test_image(50, 50, "RGB")
    output_path = os.path.join(temp_dir, "stego_empty.png")
    
    # Embed empty data
    embed_data(cover_path, b"", output_path)
    
    # Extract data
    extracted_data = extract_data(output_path)
    
    # Verify extracted data is empty
    assert extracted_data == b""

def test_output_path_extension(create_test_image, sample_data, temp_dir):
    """Test output path extension handling."""
    cover_path = create_test_image(50, 50, "RGB")

    # Test with non-PNG extension
    output_path = os.path.join(temp_dir, "stego_output.jpg")

    
    embed_data(cover_path, sample_data, output_path)

   
    png_output_path = os.path.splitext(output_path)[0] + ".png"
    assert os.path.exists(png_output_path)


if __name__ == "__main__":
    pytest.main(["-v", __file__])
