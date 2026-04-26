
import os
import tempfile

import numpy as np
import pytest
from PIL import Image

from stegx.cover_selector import (
    CoverCandidate,
    evaluate_cover,
    iter_image_paths,
    pick_best_cover,
    score_candidates,
)

@pytest.fixture
def cover_dir():
    with tempfile.TemporaryDirectory() as d:

        Image.new("RGB", (50, 50), (128, 128, 128)).save(os.path.join(d, "flat.png"))

        rng = np.random.default_rng(1)
        arr = rng.integers(0, 256, (200, 200, 3), dtype=np.uint8)
        Image.fromarray(arr, "RGB").save(os.path.join(d, "noisy_medium.png"))

        arr = rng.integers(0, 256, (400, 400, 3), dtype=np.uint8)
        Image.fromarray(arr, "RGB").save(os.path.join(d, "noisy_large.png"))

        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("ignored")
        yield d

def test_iter_image_paths_ignores_non_images(cover_dir):
    images = iter_image_paths(cover_dir)
    assert all(p.endswith(".png") for p in images)
    assert len(images) == 3

def test_evaluate_cover_returns_candidate(cover_dir):
    path = os.path.join(cover_dir, "noisy_large.png")
    c = evaluate_cover(path)
    assert c is not None
    assert c.width == 400 and c.height == 400
    assert c.mode in ("RGB", "RGBA")
    assert c.capacity_bits > 0
    assert 6.0 < c.entropy <= 8.0

def test_small_payload_prefers_high_entropy(cover_dir):


    best, ranked = pick_best_cover(cover_dir, payload_size_bytes=100)
    assert best is not None
    assert "noisy_large" in best.path or "noisy_medium" in best.path

    flat = next(c for c in ranked if "flat.png" in c.path)
    assert flat.enough_capacity
    assert flat.score < best.score

def test_oversized_payload_returns_none(cover_dir):

    best, ranked = pick_best_cover(cover_dir, payload_size_bytes=1_000_000)
    assert best is None
    assert ranked
    assert all(not c.enough_capacity for c in ranked)

def test_score_candidates_deterministic():
    fake = [
        CoverCandidate("a", 100, 100, "RGB", capacity_bits=30000, entropy=7.5,
                       score=0.0, enough_capacity=False),
        CoverCandidate("b", 200, 200, "RGB", capacity_bits=120000, entropy=3.0,
                       score=0.0, enough_capacity=False),
    ]
    ranked = score_candidates(fake, required_bits=1000)

    assert ranked[0].path == "a"
