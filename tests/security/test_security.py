#!/usr/bin/env python3
import os
import pytest
import tempfile
import shutil
import numpy as np
from PIL import Image
import random
import string
import cryptography
from cryptography.exceptions import InvalidTag

from stegx_core.crypto import encrypt_data, decrypt_data, derive_key
from stegx_core.steganography import embed_data, extract_data
from stegx import perform_encode, perform_decode

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname

@pytest.fixture
def sample_data():
    return b"StegX security test data 1234567890!@#$%^&*()"

@pytest.fixture
def test_file(temp_dir, sample_data):
    file_path = os.path.join(temp_dir, "test_file.txt")
    with open(file_path, "wb") as f:
        f.write(sample_data)
    return file_path

@pytest.fixture
def test_image(temp_dir):
    from PIL import Image
    import numpy as np

    width, height = 100, 100
    img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(img_array, "RGB")

    image_path = os.path.join(temp_dir, "cover_image.png")
    img.save(image_path)
    
    return image_path

@pytest.mark.security
def test_password_strength():
    passwords = [
        "a",
        "password",
        "Password123",
        "P@ssw0rd!2#4",
        "X" * 64,
        "".join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))  # Random
    ]

    salt = b"0123456789abcdef"

    results = []
    for password in passwords:
        key = derive_key(password, salt)

        entropy = 0
        byte_counts = {}
        for byte in key:
            if byte not in byte_counts:
                byte_counts[byte] = 0
            byte_counts[byte] += 1
        
        for count in byte_counts.values():
            probability = count / len(key)
            entropy -= probability * np.log2(probability)

        uniqueness = len(byte_counts) / 256 * 100
        
        results.append({
            "password": password,
            "length": len(password),
            "entropy": entropy,
            "uniqueness": uniqueness,
            "key_hex": key.hex()[:16] + "..."
        })

    print("\nPassword Strength Analysis:")
    print("--------------------------")
    for result in results:
        print("Password: [REDACTED]")
        print(f"  Length: {result['length']}")
        print(f"  Key Entropy: {result['entropy']:.2f} bits/byte")
        print(f"  Uniqueness: {result['uniqueness']:.2f}%")
        print("  Key (partial): [REDACTED]")

    keys = [result["key_hex"] for result in results]
    assert len(keys) == len(set(keys)), "Some keys are identical despite different passwords"

@pytest.mark.security
def test_crypto_robustness(temp_dir, sample_data):
    password = "correct_password"
    encrypted = encrypt_data(sample_data, password)

    assert encrypted != sample_data

    decrypted = decrypt_data(encrypted, password)
    assert decrypted == sample_data

    wrong_password = "wrong_password"
    try:
        decrypt_data(encrypted, wrong_password)
        assert False, "Decryption should fail with wrong password"
    except (ValueError, cryptography.exceptions.InvalidTag):
        pass


# Test for resistance to tampering
@pytest.mark.security
def test_tamper_resistance(create_test_image, sample_data, temp_dir):
    cover_path = create_test_image(100, 100, "RGB")
    stego_path = os.path.join(temp_dir, "stego_tamper.png")
    extract_dir = os.path.join(temp_dir, "extracted_tampered")
    os.makedirs(extract_dir, exist_ok=True)

    password = "test_password"
    encrypted_data = encrypt_data(sample_data, password)
    embed_data(cover_path, encrypted_data, stego_path)

    tampered_path = os.path.join(temp_dir, "tampered.png")
    shutil.copy(stego_path, tampered_path)

    image = Image.open(tampered_path)
    pixels = image.load()
    width, height = image.size

    for i in range(width // 5):
        for j in range(height):
            if image.mode == 'RGB':
                pixels[i, j] = (255, 0, 0)
            elif image.mode == 'RGBA':
                pixels[i, j] = (255, 0, 0, 255)
            else:
                pixels[i, j] = 255
    
    image.save(tampered_path)

    try:
        extract_data(tampered_path)
        assert False, "Decoding succeeded despite heavy tampering"
    except ValueError:
        pass

@pytest.mark.security
def test_steganalysis_resistance(test_file, test_image, temp_dir):
    password = "StegXTestPassword123!@#"
    stego_path = os.path.join(temp_dir, "stego_analysis.png")

    success = perform_encode(test_image, test_file, stego_path, password, compress=True)
    assert success, "Encoding failed"

    cover_img = Image.open(test_image)
    stego_img = Image.open(stego_path)

    assert cover_img.size == stego_img.size, "Image dimensions changed"
    assert cover_img.mode == stego_img.mode, "Image mode changed"

    cover_array = np.array(cover_img)
    stego_array = np.array(stego_img)

    if cover_img.mode in ("RGB", "RGBA"):
        channels = 3
    else:
        channels = 1
    
    for channel in range(channels):
        if channels == 1:
            cover_channel = cover_array
            stego_channel = stego_array
        else:
            cover_channel = cover_array[:, :, channel]
            stego_channel = stego_array[:, :, channel]
        
        cover_hist, _ = np.histogram(cover_channel, bins=256, range=(0, 256))
        stego_hist, _ = np.histogram(stego_channel, bins=256, range=(0, 256))

        correlation = np.corrcoef(cover_hist, stego_hist)[0, 1]
        print(f"Channel {channel} histogram correlation: {correlation:.6f}")

        assert correlation >= 0.96, f"Channel {channel} histograms differ significantly"

    cover_lsbs = cover_array & 1
    stego_lsbs = stego_array & 1

    total_pixels = cover_lsbs.size
    changed_lsbs = np.sum(cover_lsbs != stego_lsbs)
    change_percentage = changed_lsbs / total_pixels * 100
    
    print(f"LSB change percentage: {change_percentage:.2f}%")

    assert 1 < change_percentage < 60, "LSB change percentage outside expected range"

    pairs = {}
    for i in range(0, 256, 2):
        pairs[i] = 0
        pairs[i+1] = 0

    if channels == 1:
        for pixel in stego_array.flatten():
            pairs[pixel] += 1
    else:
        for pixel in stego_array[:, :, 0].flatten():
            pairs[pixel] += 1

    chi_square = 0
    for i in range(0, 256, 2):
        expected = (pairs[i] + pairs[i+1]) / 2
        if expected > 0:
            chi_square += ((pairs[i] - expected)**2 + (pairs[i+1] - expected)**2) / expected
    
    print(f"Chi-square statistic: {chi_square:.2f}")
    

@pytest.mark.security
def test_malformed_input_handling(temp_dir):

    malformed_image = os.path.join(temp_dir, "malformed.png")
    with open(malformed_image, "wb") as f:
        f.write(b"PNG\r\n\x1a\n" + os.urandom(100))

    extract_dir = os.path.join(temp_dir, "extracted_malformed")
    os.makedirs(extract_dir, exist_ok=True)

    result = perform_decode(malformed_image, extract_dir, "password")
    assert not result, "Decoding succeeded with malformed image"

    large_password = "X" * 10000

    test_file = os.path.join(temp_dir, "test_large_pw.txt")
    with open(test_file, "wb") as f:
        f.write(b"Test data")

    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    test_image = os.path.join(temp_dir, "test_large_pw.png")
    img.save(test_image)
    
    stego_path = os.path.join(temp_dir, "stego_large_pw.png")

    try:
        result = perform_encode(test_image, test_file, stego_path, large_password, compress=True)
        if result:
            print("Large password handled successfully")

            result = perform_decode(stego_path, extract_dir, large_password)
            assert result, "Decoding failed with large password"
        else:
            print("Encoding failed with large password, but did not crash")
    except Exception as e:
        assert False, f"Large password caused unhandled exception: {e}"

    non_image = os.path.join(temp_dir, "non_image.txt")
    with open(non_image, "wb") as f:
        f.write(b"This is not an image file")

    result = perform_decode(non_image, extract_dir, "password")
    assert not result, "Decoding succeeded with non-image file"

@pytest.mark.security
def test_command_injection_resistance(temp_dir):

    test_image = os.path.join(temp_dir, "test_image.png")
    Image.new('RGB', (50, 50), color='white').save(test_image)

    test_file = os.path.join(temp_dir, "test_file.txt")
    with open(test_file, 'w') as f:
        f.write("Test content")

    dangerous_input = os.path.join(temp_dir, "file; rm -rf /")
    safe_output = os.path.join(temp_dir, "safe_output.png")


    from stegx import sanitize_filename
    safe_name = sanitize_filename(dangerous_input)

    assert ";" not in safe_name
    assert "/" not in safe_name
    assert safe_name != dangerous_input

    try:
        sanitize_filename(temp_dir)
        assert False, "Should raise ValueError for directories"
    except ValueError:
        pass


if __name__ == "__main__":
    pytest.main(["-v", __file__])
