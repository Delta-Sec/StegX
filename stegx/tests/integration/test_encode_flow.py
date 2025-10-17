#!/usr/bin/env python3
import os
import pytest
import tempfile

from stegx_core.steganography import embed_data, extract_data
from stegx_core.crypto import encrypt_data, decrypt_data
from stegx_core.utils import create_payload, parse_payload

from stegx import perform_encode, perform_decode

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname

@pytest.fixture
def sample_data():
    return b"StegX integration test data 1234567890!@#$%^&*()"

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

def test_encode_flow_integration(test_file, test_image, temp_dir, sample_data):
    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_output.png")

    payload = create_payload(test_file, compress=True)

    encrypted_payload = encrypt_data(payload, password)

    embed_data(test_image, encrypted_payload, output_path)

    assert os.path.exists(output_path)

    extracted_encrypted_payload = extract_data(output_path)

    decrypted_payload = decrypt_data(extracted_encrypted_payload, password)

    filename, file_data = parse_payload(decrypted_payload)

    assert file_data == sample_data
    assert filename == os.path.basename(test_file)

def test_high_level_encode_decode_integration(test_file, test_image, temp_dir, sample_data):
    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_output.png")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    success = perform_encode(test_image, test_file, output_path, password, compress=True)

    assert success
    assert os.path.exists(output_path)

    success = perform_decode(output_path, extract_dir, password)

    assert success

    extracted_file_path = os.path.join(extract_dir, os.path.basename(test_file))
    assert os.path.exists(extracted_file_path)
    
    with open(extracted_file_path, "rb") as f:
        extracted_data = f.read()
    
    assert extracted_data == sample_data

def test_encode_flow_error_handling(test_file, test_image, temp_dir):
    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_output.png")

    non_existent_file = os.path.join(temp_dir, "non_existent.txt")
    success = perform_encode(test_image, non_existent_file, output_path, password, compress=True)
    assert not success

    non_existent_image = os.path.join(temp_dir, "non_existent.png")
    success = perform_encode(non_existent_image, test_file, output_path, password, compress=True)
    assert not success

    success = perform_encode(test_image, test_file, output_path, "", compress=True)
    assert not success

@pytest.mark.parametrize("file_extension,file_content", [
    (".txt", b"Plain text content"),
    (".json", b'{"key": "value"}'),
    (".bin", bytes(range(256))),
    (".pdf", b"%PDF-1.5\n%Test PDF content")
])
def test_encode_decode_different_file_types(temp_dir, test_image, file_extension, file_content):

    test_file = os.path.join(temp_dir, f"test_file{file_extension}")
    with open(test_file, "wb") as f:
        f.write(file_content)

    password = "StegXTestPassword123!@#"
    output_path = os.path.join(temp_dir, "stego_output.png")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    success = perform_encode(test_image, test_file, output_path, password, compress=True)
    assert success

    success = perform_decode(output_path, extract_dir, password)
    assert success

    extracted_file_path = os.path.join(extract_dir, os.path.basename(test_file))
    assert os.path.exists(extracted_file_path)
    
    with open(extracted_file_path, "rb") as f:
        extracted_data = f.read()
    
    assert extracted_data == file_content


if __name__ == "__main__":
    pytest.main(["-v", __file__])
