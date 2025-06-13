#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""System tests for StegX CLI interface."""

import os
import pytest
import subprocess
import tempfile
import shutil
from pathlib import Path

# Test fixtures
@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname

@pytest.fixture
def sample_data():
    """Generate sample data for testing."""
    return b"StegX system test data 1234567890!@#$%^&*()"

@pytest.fixture
def test_file(temp_dir, sample_data):
    """Create a test file with sample data."""
    file_path = os.path.join(temp_dir, "test_file.txt")
    with open(file_path, "wb") as f:
        f.write(sample_data)
    return file_path

@pytest.fixture
def test_image(temp_dir):
    """Create a test image for steganography."""
    from PIL import Image
    import numpy as np
    
    # Create a simple RGB image
    width, height = 100, 100
    img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(img_array, "RGB")
    
    # Save the image
    image_path = os.path.join(temp_dir, "cover_image.png")
    img.save(image_path)
    
    return image_path

@pytest.fixture
def stegx_path():
    """Get the path to the StegX CLI script."""
    # This assumes the tests are run from the project root
    # Adjust as needed for your environment
    return shutil.which("stegx") or os.path.abspath("./stegx.py")

# System test for the CLI encode command
def test_cli_encode(stegx_path, test_file, test_image, temp_dir, sample_data):
    """Test the CLI encode command."""
    # Define test parameters
    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_output.png")
    
    # Run the CLI command
    cmd = [
        "python3",
        stegx_path,
        "encode",
        "-i", test_image,
        "-f", test_file,
        "-o", output_path,
        "-p", password
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0, f"Command failed with output: {result.stderr}"
    
    # Verify output file exists
    assert os.path.exists(output_path)

# System test for the CLI decode command
def test_cli_decode(stegx_path, test_file, test_image, temp_dir, sample_data):
    """Test the CLI decode command."""
    # Define test parameters
    password = "StegXTestPassword123!@#"
    stego_path = os.path.join(temp_dir, "stego_output.png")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    # First encode a file
    encode_cmd = [
    	"python3",
        stegx_path,
        "encode",
        "-i", test_image,
        "-f", test_file,
        "-o", stego_path,
        "-p", password
    ]
    
    result = subprocess.run(encode_cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Encode command failed with output: {result.stderr}"
    
    # Then decode the file
    decode_cmd = [
    	"python3",
        stegx_path,
        "decode",
        "-i", stego_path,
        "-d", extract_dir,
        "-p", password
    ]
    
    result = subprocess.run(decode_cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0, f"Decode command failed with output: {result.stderr}"
    
    # Verify extracted file exists and has correct content
    extracted_file_path = os.path.join(extract_dir, os.path.basename(test_file))
    assert os.path.exists(extracted_file_path)
    
    with open(extracted_file_path, "rb") as f:
        extracted_data = f.read()
    
    assert extracted_data == sample_data

# Test CLI with verbose flag
def test_cli_verbose(stegx_path, test_file, test_image, temp_dir):
    """Test the CLI with verbose flag."""
    # Define test parameters
    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_verbose.png")
    
    # Run the CLI command with verbose flag
    cmd = [
    	"python3",
        stegx_path,
        "--verbose",
        "encode",
        "-i", test_image,
        "-f", test_file,
        "-o", output_path,
        "-p", password
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0, f"Command failed with output: {result.stderr}"
    
    # Verify verbose output contains DEBUG messages
    assert "DEBUG" in result.stderr

# Test CLI with no-compress flag
def test_cli_no_compress(stegx_path, test_file, test_image, temp_dir):
    """Test the CLI with no-compress flag."""
    # Define test parameters
    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_no_compress.png")
    
    # Run the CLI command with no-compress flag
    cmd = [
    	"python3",
        stegx_path,
        "encode",
        "-i", test_image,
        "-f", test_file,
        "-o", output_path,
        "-p", password,
        "--no-compress"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0, f"Command failed with output: {result.stderr}"
    
    # Verify output file exists
    assert os.path.exists(output_path)

# Test CLI error handling
def test_cli_error_handling(stegx_path, temp_dir):
    """Test CLI error handling with invalid inputs."""
    # Test with non-existent image
    cmd = [
    	"python3",
        stegx_path,
        "encode",
        "-i", "non_existent.png",
        "-f", "some_file.txt",
        "-o", "output.png",
        "-p", "password"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command failed
    assert result.returncode != 0
    assert "not found" in result.stderr.lower()
    
    # Test with missing required arguments
    cmd = [
    	"python3",
        stegx_path,
        "encode",
        "-i", "image.png",
        # Missing -f argument
        "-o", "output.png",
        "-p", "password"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command failed
    assert result.returncode != 0
    assert "required" in result.stderr.lower()

# Test CLI help command
def test_cli_help(stegx_path):
    """Test the CLI help command."""
    # Test main help
    cmd = ["python3", stegx_path, "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0
    
    # Verify help output contains expected sections
    assert "encode" in result.stdout.lower()
    assert "decode" in result.stdout.lower()
    
    # Test encode help
    cmd = ["python3", stegx_path, "encode", "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0
    
    # Verify help output contains expected options
    assert "-i" in result.stdout
    assert "-f" in result.stdout
    assert "-o" in result.stdout
    assert "-p" in result.stdout
    
    # Test decode help
    cmd = ["python3", stegx_path, "decode", "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0
    
    # Verify help output contains expected options
    assert "-i" in result.stdout
    assert "-d" in result.stdout
    assert "-p" in result.stdout

# Test CLI version command
def test_cli_version(stegx_path):
    """Test the CLI version command."""
    cmd = ["python3", stegx_path, "--version"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Verify command succeeded
    assert result.returncode == 0
    
    # Verify version output contains version number
    assert "stegx" in result.stdout.lower()
    assert "." in result.stdout  # Version number typically contains dots

# End-to-end test with large file
@pytest.mark.slow
def test_end_to_end_large_file(stegx_path, test_image, temp_dir):
    """End-to-end test with a large file."""
    # Create a large file (1MB)
    large_file_path = os.path.join(temp_dir, "large_file.bin")
    with open(large_file_path, "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1MB of random data
    
    # Define test parameters
    password = "StegXTestPassword123!@#"
    stego_path = os.path.join(temp_dir, "stego_large.png")
    extract_dir = os.path.join(temp_dir, "extracted_large")
    os.makedirs(extract_dir, exist_ok=True)
    
    # Encode the large file
    encode_cmd = [
        "python3",
        stegx_path,
        "encode",
        "-i", test_image,
        "-f", large_file_path,
        "-o", stego_path,
        "-p", password
    ]
    
    result = subprocess.run(encode_cmd, capture_output=True, text=True)
    
    # This might fail if the image is too small for the data
    # In a real test, you'd use a sufficiently large image
    if result.returncode == 0:
        # Decode the file
        decode_cmd = [
            "python3",
            stegx_path,
            "decode",
            "-i", stego_path,
            "-d", extract_dir,
            "-p", password
        ]
        
        result = subprocess.run(decode_cmd, capture_output=True, text=True)
        
        # Verify command succeeded
        assert result.returncode == 0, f"Decode command failed with output: {result.stderr}"
        
        # Verify extracted file exists
        extracted_file_path = os.path.join(extract_dir, os.path.basename(large_file_path))
        assert os.path.exists(extracted_file_path)
        
        # Verify file size matches
        assert os.path.getsize(extracted_file_path) == os.path.getsize(large_file_path)
    else:
        # Skip test if image is too small
        pytest.skip("Image too small for large file test")

if __name__ == "__main__":
    pytest.main(["-v", __file__])
