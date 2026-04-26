from __future__ import annotations

import hashlib
import random
from typing import List, Sequence, Tuple

Position = Tuple[int, int, int]

def _region_rng(cover_fingerprint: bytes) -> random.Random:
    seed_bytes = hashlib.sha256(b"stegx/v2/decoy-split\x00" + cover_fingerprint).digest()
    return random.Random(int.from_bytes(seed_bytes[:16], "big"))

def split_regions(
    all_positions: Sequence[Position],
    cover_fingerprint: bytes,
) -> Tuple[List[Position], List[Position]]:
    indices = list(range(len(all_positions)))
    _region_rng(cover_fingerprint).shuffle(indices)
    half = len(indices) // 2
    decoy_idx = sorted(indices[:half])
    real_idx = sorted(indices[half:])
    decoy_region = [all_positions[i] for i in decoy_idx]
    real_region = [all_positions[i] for i in real_idx]
    return decoy_region, real_region

def reorder_region(region: Sequence[Position], seed_int: int) -> List[Position]:
    region_list = list(region)
    random.Random(seed_int).shuffle(region_list)
    return region_list
