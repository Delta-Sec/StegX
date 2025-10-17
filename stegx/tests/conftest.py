#!/usr/bin/env python3
import os
import pytest
from PIL import Image


@pytest.fixture
def temp_dir(tmpdir):
    return str(tmpdir)


@pytest.fixture
def sample_data():
    return b'StegX security test data 1234567890!@#$%^&*()'


@pytest.fixture
def test_file(temp_dir):
    file_path = os.path.join(temp_dir, "test_file.txt")
    with open(file_path, 'w') as f:
        f.write("Plain text content")
    return file_path


@pytest.fixture
def test_image(temp_dir):
    image_path = os.path.join(temp_dir, "cover_image.png")
    image = Image.new('RGB', (100, 100), color='white')
    image.save(image_path)
    return image_path


@pytest.fixture
def create_test_image(temp_dir):
    def _create_image(width, height, mode="RGB"):
        image_path = os.path.join(temp_dir, f"test_image_{width}x{height}_{mode}.png")
        image = Image.new(mode, (width, height), color='white')
        image.save(image_path)
        return image_path
    return _create_image
