from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from PIL import Image, UnidentifiedImageError

_IMAGE_EXTENSIONS = frozenset(
    {".png", ".bmp", ".tif", ".tiff", ".gif", ".webp", ".ppm", ".jpg", ".jpeg"}
)

@dataclass
class CoverCandidate:
    path: str
    width: int
    height: int
    mode: str
    capacity_bits: int
    entropy: float
    score: float
    enough_capacity: bool

def iter_image_paths(directory: str) -> List[str]:
    results = []
    for name in sorted(os.listdir(directory)):
        _root, ext = os.path.splitext(name)
        if ext.lower() in _IMAGE_EXTENSIONS:
            full = os.path.join(directory, name)
            if os.path.isfile(full):
                results.append(full)
    return results

def _shannon_entropy(histogram: Iterable[int]) -> float:
    total = float(sum(histogram))
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in histogram:
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def _image_entropy(image: Image.Image, sample_side: int = 256) -> float:
    w, h = image.size
    if max(w, h) > sample_side:
        scale = sample_side / max(w, h)
        image = image.resize(
            (max(1, int(w * scale)), max(1, int(h * scale))),
            Image.Resampling.BILINEAR,
        )
    gray = image.convert("L")
    return _shannon_entropy(gray.histogram())

def _capacity_bits_for(width: int, height: int, mode: str) -> int:
    if mode in ("RGB", "RGBA", "P"):
        channels = 3
    elif mode == "L":
        channels = 1
    else:
        return 0


    reserved_bits = (16 + 56) * 8
    return max(0, width * height * channels - reserved_bits)

def evaluate_cover(path: str) -> Optional[CoverCandidate]:
    try:
        with Image.open(path) as img:
            img.load()
            width, height = img.size
            mode = img.mode
            if mode not in ("RGB", "RGBA", "L", "P"):
                logging.debug("Skipping %s: unsupported mode %s", path, mode)
                return None
            capacity = _capacity_bits_for(width, height, mode)
            if capacity <= 0:
                return None
            entropy = _image_entropy(img.convert("RGB") if mode == "P" else img)
    except (UnidentifiedImageError, OSError) as e:
        logging.debug("Skipping %s: %s", path, e)
        return None

    return CoverCandidate(
        path=path,
        width=width,
        height=height,
        mode=mode,
        capacity_bits=capacity,
        entropy=entropy,
        score=0.0,
        enough_capacity=False,
    )

def score_candidates(
    candidates: List[CoverCandidate],
    required_bits: int,
) -> List[CoverCandidate]:
    scored = []
    for c in candidates:
        enough = c.capacity_bits > required_bits
        if enough and required_bits > 0:
            headroom = max(c.capacity_bits / required_bits, 1.0)
            score = c.entropy * math.log2(headroom + 1.0)
        else:
            score = 0.0
        scored.append(
            CoverCandidate(
                path=c.path,
                width=c.width,
                height=c.height,
                mode=c.mode,
                capacity_bits=c.capacity_bits,
                entropy=c.entropy,
                score=score,
                enough_capacity=enough,
            )
        )
    scored.sort(
        key=lambda x: (0 if x.enough_capacity else 1, -x.score),
    )
    return scored

def pick_best_cover(
    directory: str,
    payload_size_bytes: int,
) -> Tuple[Optional[CoverCandidate], List[CoverCandidate]]:
    required_bits = payload_size_bytes * 8
    raw = []
    for path in iter_image_paths(directory):
        cand = evaluate_cover(path)
        if cand is not None:
            raw.append(cand)
    ranked = score_candidates(raw, required_bits)
    best = ranked[0] if ranked and ranked[0].enough_capacity else None
    return best, ranked
