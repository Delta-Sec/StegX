from __future__ import annotations

import random
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

from PIL import Image, ImageFilter

Position = Tuple[int, int, int]

LSB_MATCHING = "lsb_matching"
LSB_REPLACEMENT = "lsb_replacement"
MATRIX_HAMMING = "matrix_hamming"

def _get_lsb(pixels, x: int, y: int, c: int, is_gray: bool) -> int:
    if is_gray:
        return pixels[x, y] & 1
    return pixels[x, y][c] & 1

def _set_lsb_replacement(pixels, x: int, y: int, c: int, is_gray: bool, bit: int) -> None:
    if is_gray:
        v = pixels[x, y]
        pixels[x, y] = (v & ~1) | bit
        return
    pixel = list(pixels[x, y])
    pixel[c] = (pixel[c] & ~1) | bit
    pixels[x, y] = tuple(pixel)

def _adjust_pm1(pixels, x: int, y: int, c: int, is_gray: bool, rng: random.Random) -> None:
    if is_gray:
        v = pixels[x, y]
        if v == 0:
            new = 1
        elif v == 255:
            new = 254
        else:
            new = v + (1 if rng.random() < 0.5 else -1)
        pixels[x, y] = new
        return
    pixel = list(pixels[x, y])
    v = pixel[c]
    if v == 0:
        new = 1
    elif v == 255:
        new = 254
    else:
        new = v + (1 if rng.random() < 0.5 else -1)
    pixel[c] = new
    pixels[x, y] = tuple(pixel)

def embed_bits(
    pixels,
    mode: str,
    positions: Sequence[Position],
    bits: str,
    method: str,
    rng: random.Random,
) -> int:
    is_gray = mode == "L"
    if method == MATRIX_HAMMING:
        return _embed_matrix_hamming(pixels, positions, bits, is_gray, rng, k=3)

    count = 0
    for ch in bits:
        if count >= len(positions):
            raise ValueError("Ran out of positions while embedding bits.")
        x, y, c = positions[count]
        target = 1 if ch == "1" else 0
        current = _get_lsb(pixels, x, y, c, is_gray)
        if current != target:
            if method == LSB_MATCHING:
                _adjust_pm1(pixels, x, y, c, is_gray, rng)
            elif method == LSB_REPLACEMENT:
                _set_lsb_replacement(pixels, x, y, c, is_gray, target)
            else:
                raise ValueError(f"Unknown embedding method: {method}")
        count += 1
    return count

def extract_bits(
    pixels,
    mode: str,
    positions: Sequence[Position],
    nbits: int,
    method: str,
) -> str:
    is_gray = mode == "L"
    if method == MATRIX_HAMMING:
        return _extract_matrix_hamming(pixels, positions, nbits, is_gray, k=3)

    out = []
    for i in range(nbits):
        x, y, c = positions[i]
        out.append("1" if _get_lsb(pixels, x, y, c, is_gray) else "0")
    return "".join(out)

def positions_needed(nbits: int, method: str, k: int = 3) -> int:
    if method == MATRIX_HAMMING:
        block_cover = (1 << k) - 1
        blocks = (nbits + k - 1) // k
        return blocks * block_cover
    return nbits

def _embed_matrix_hamming(
    pixels,
    positions: Sequence[Position],
    bits: str,
    is_gray: bool,
    rng: random.Random,
    k: int,
) -> int:
    block_cover = (1 << k) - 1
    pos_idx = 0
    bit_idx = 0
    total_bits = len(bits)
    while bit_idx < total_bits:
        if pos_idx + block_cover > len(positions):
            raise ValueError("Ran out of positions for matrix-embedding block.")
        block_positions = positions[pos_idx : pos_idx + block_cover]

        cover_lsbs = [_get_lsb(pixels, x, y, c, is_gray) for (x, y, c) in block_positions]
        message_slice = bits[bit_idx : bit_idx + k]
        if len(message_slice) < k:
            message_slice = message_slice + "0" * (k - len(message_slice))
        message_int = int(message_slice, 2)

        syndrome = 0
        for i, lsb in enumerate(cover_lsbs, start=1):
            if lsb:
                syndrome ^= i
        flip_pos = syndrome ^ message_int
        if flip_pos != 0:
            x, y, c = block_positions[flip_pos - 1]
            _adjust_pm1(pixels, x, y, c, is_gray, rng)

        pos_idx += block_cover
        bit_idx += k
    return total_bits

def _extract_matrix_hamming(
    pixels,
    positions: Sequence[Position],
    nbits: int,
    is_gray: bool,
    k: int,
) -> str:
    block_cover = (1 << k) - 1
    pos_idx = 0
    bits_out: List[str] = []
    remaining = nbits
    while remaining > 0:
        block_positions = positions[pos_idx : pos_idx + block_cover]
        if len(block_positions) < block_cover:
            raise ValueError("Ran out of positions for matrix-extraction block.")
        syndrome = 0
        for i, (x, y, c) in enumerate(block_positions, start=1):
            if _get_lsb(pixels, x, y, c, is_gray):
                syndrome ^= i
        chunk = format(syndrome, f"0{k}b")
        take = min(k, remaining)
        bits_out.append(chunk[:take])
        remaining -= take
        pos_idx += block_cover
    return "".join(bits_out)

COST_LAPLACIAN = "laplacian"
COST_HILL = "hill"

def _lsb_cleared_gray(image: Image.Image) -> Image.Image:
    if image.mode in ("RGB", "RGBA"):
        r, g, b = image.split()[:3]
        r = r.point(lambda v: v & 0xFE)
        g = g.point(lambda v: v & 0xFE)
        b = b.point(lambda v: v & 0xFE)
        cleared = Image.merge("RGB", (r, g, b))
        return cleared.convert("L").point(lambda v: v & 0xFE)
    gray = image.convert("L")
    return gray.point(lambda v: v & 0xFE)

def _hill_cost_map(image: Image.Image) -> Image.Image:
    gray = _lsb_cleared_gray(image)
    kb_kernel = (-1, 2, -1, 2, -4, 2, -1, 2, -1)

    residual_img = gray.filter(ImageFilter.Kernel((3, 3), kb_kernel, scale=1, offset=128))
    width, height = residual_img.size


    abs_res = bytes(min(255, abs(p - 128)) for p in residual_img.getdata())
    abs_img = Image.frombytes("L", (width, height), abs_res)


    w1 = abs_img.filter(ImageFilter.BoxBlur(1))


    w1_data = list(w1.getdata())
    eps = 1.0
    inv = [1.0 / (v + eps) for v in w1_data]


    peak = 1.0 / eps
    inv_bytes = bytes(min(255, max(0, int(v * 255.0 / peak))) for v in inv)
    inv_img = Image.frombytes("L", (width, height), inv_bytes)


    blurred = inv_img.filter(ImageFilter.BoxBlur(7))
    return blurred.point(lambda v: v & 0xFC)

def _laplacian_edge_map(image: Image.Image) -> Image.Image:


    edges = _lsb_cleared_gray(image).filter(ImageFilter.FIND_EDGES)
    return edges.point(lambda v: v & 0xFC)

def build_adaptive_position_mask(
    image: Image.Image,
    min_cost_percentile: float = 0.40,
    cost_mode: str = COST_LAPLACIAN,
) -> "set[Tuple[int, int]]":
    if not (0.0 <= min_cost_percentile < 1.0):
        raise ValueError("min_cost_percentile must be in [0, 1)")

    if cost_mode == COST_HILL:
        cost_img = _hill_cost_map(image)
        data = list(cost_img.getdata())
        if not data:
            raise ValueError("Empty cost map — image has no pixels.")
        sorted_vals = sorted(data)


        if sorted_vals[0] == sorted_vals[-1]:
            accept = lambda v: True
        else:

            keep_top = int(len(sorted_vals) * (1.0 - min_cost_percentile))
            keep_top = max(1, keep_top)
            cutoff = sorted_vals[keep_top - 1]
            accept = lambda v: v <= cutoff
    elif cost_mode == COST_LAPLACIAN:
        cost_img = _laplacian_edge_map(image)
        data = list(cost_img.getdata())
        if not data:
            raise ValueError("Empty cost map — image has no pixels.")
        sorted_vals = sorted(data)


        if sorted_vals[0] == sorted_vals[-1]:
            accept = lambda v: True
        else:

            cutoff_idx = int(len(sorted_vals) * min_cost_percentile)
            cutoff = sorted_vals[cutoff_idx] if cutoff_idx < len(sorted_vals) else 0
            if cutoff <= 0:
                cutoff = 1
            accept = lambda v: v >= cutoff
    else:
        raise ValueError(f"Unknown cost_mode: {cost_mode!r}")

    width, _height = cost_img.size
    mask = set()
    for idx, v in enumerate(data):
        if accept(v):
            mask.add((idx % width, idx // width))
    return mask

def filter_positions_by_mask(
    positions: Iterable[Position],
    mask: "set[Tuple[int, int]]",
) -> Iterator[Position]:
    for pos in positions:
        if (pos[0], pos[1]) in mask:
            yield pos

def iter_positions_in_order(
    positions: Sequence[Position],
    mask: Optional["set[Tuple[int, int]]"],
) -> List[Position]:
    if mask is None:
        return list(positions)
    return [p for p in positions if (p[0], p[1]) in mask]
