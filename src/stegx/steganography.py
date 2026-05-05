from __future__ import annotations

import hashlib
import logging
import os
import random
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from PIL import Image
from cryptography.exceptions import InvalidTag

from . import embedding as emb
from .compression import MODE_BEST as _CX_MODE_BEST, MODE_FAST as _CX_MODE_FAST
from .constants import (
    HEAD_BYTES_V2,
    HEAD_BYTES_V3,
    HEADER_SALT_LEN,
    HEADER_SIZE_V2,
    HEADER_SIZE_V3_BASE,
    KMS_WRAP_MAX,
    YK_CHALLENGE_NONCE_LEN,
)
from .cover_preserve import save_as_stego_png, sniff_png_encoder
from .crypto import EncryptOptions, decrypt_data, decrypt_legacy_v1, encrypt_data
from .exceptions import (
    CorruptedPayload,
    InsufficientCapacity,
    UnsupportedImageMode,
)
from .decoy import reorder_region, split_regions
from .embedding import (
    LSB_MATCHING,
    LSB_REPLACEMENT,
    MATRIX_HAMMING,
    build_adaptive_position_mask,
    embed_bits,
    extract_bits,
    positions_needed,
)
from .header import FLAG_ADAPTIVE, FLAG_MATRIX, FLAG_YUBIKEY, Header
from .kdf import (
    HKDF_INFO_DECOY_SEED,
    HKDF_INFO_SEED,
    HKDF_INFO_SENTINEL,
    KdfParams,
    derive_legacy_seed_from_password,
    derive_master_key,
    hkdf_subkey,
    seed_int_from_subkey,
)
from .secure_memory import SecureBuffer
from .sentinel import (
    SENTINEL_BITS,
    SENTINEL_LEN,
    bits_match_sentinel,
    bytes_to_bits,
    cover_fingerprint,
    derive_sentinel,
)

DATA_SENTINEL = b"\x53\x54\x45\x47\x58\x5f\x45\x4f\x44"
SENTINEL_LENGTH_BITS = len(DATA_SENTINEL) * 8
_POSITION_KDF_APP_KEY = b"stegx/v2/position-kdf"
_POSITION_KDF_PARAMS = KdfParams.default_argon2id()


_HEAD_PEEK_BYTES = HEADER_SIZE_V3_BASE

def _head_byte_count_from_embed(embed_bytes: bytes) -> int:
    if len(embed_bytes) <= SENTINEL_LEN + 1:
        return HEAD_BYTES_V2
    version_byte = embed_bytes[SENTINEL_LEN + 1]
    if version_byte == 0x03 and len(embed_bytes) >= SENTINEL_LEN + HEADER_SIZE_V3_BASE:
        kms_wrap_len = int.from_bytes(
            embed_bytes[SENTINEL_LEN + 88 : SENTINEL_LEN + 90], "big"
        )
        return SENTINEL_LEN + HEADER_SIZE_V3_BASE + kms_wrap_len
    if version_byte == 0x03:
        return HEAD_BYTES_V3
    return HEAD_BYTES_V2

Position = Tuple[int, int, int]


def bits_to_bytes(bits) -> bytes:
    def _as_int(b) -> int:

        if isinstance(b, str):
            return 1 if b == "1" else 0
        return 1 if b else 0

    n = len(bits) // 8
    out = bytearray(n)
    for i in range(n):
        base = i * 8
        byte = (
            _as_int(bits[base])     << 7
            | _as_int(bits[base + 1]) << 6
            | _as_int(bits[base + 2]) << 5
            | _as_int(bits[base + 3]) << 4
            | _as_int(bits[base + 4]) << 3
            | _as_int(bits[base + 5]) << 2
            | _as_int(bits[base + 6]) << 1
            | _as_int(bits[base + 7])
        )
        out[i] = byte
    return bytes(out)

def bytes_to_bits_iterator(byte_data: bytes):
    for byte in byte_data:
        for i in range(8):
            yield (byte >> (7 - i)) & 1


def calculate_lsb_capacity(image: Image.Image) -> int:
    width, height = image.size
    mode = image.mode
    if mode in ("RGB", "RGBA"):
        capacity = width * height * 3
    elif mode == "L":
        capacity = width * height
    else:
        raise UnsupportedImageMode(
            f"Unsupported image mode for LSB: {mode}. Convert to RGB or L first."
        )
    effective = capacity - HEAD_BYTES_V3 * 8
    return max(0, effective)

def _open_cover(path: str) -> Image.Image:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Cover image not found: {path}")
    image = Image.open(path)
    if image.mode == "P":
        image = image.convert("RGBA")
    elif image.mode not in ("RGB", "RGBA", "L"):
        raise UnsupportedImageMode(
            f"Unsupported image mode: {image.mode}. Use RGB/RGBA/L/P."
        )
    return image

def _all_positions(image: Image.Image) -> List[Position]:
    width, height = image.size
    channels = 3 if image.mode in ("RGB", "RGBA") else 1
    positions: List[Position] = []
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                positions.append((x, y, c))
    return positions

def _shuffle_positions(positions: List[Position], seed_int: int) -> List[Position]:
    local = list(positions)
    random.Random(seed_int).shuffle(local)
    return local


def _apply_adaptive(
    positions: List[Position],
    image: Image.Image,
    cutoff: float,
    cost_mode: str = emb.COST_LAPLACIAN,
) -> Optional[List[Position]]:
    mask = build_adaptive_position_mask(
        image, min_cost_percentile=cutoff, cost_mode=cost_mode
    )
    if not mask:
        return None
    filtered = [p for p in positions if (p[0], p[1]) in mask]
    if not filtered:
        return None
    return filtered


def _derive_position_salt(fingerprint: bytes) -> bytes:
    return hashlib.sha256(
        _POSITION_KDF_APP_KEY + b"\x00" + fingerprint
    ).digest()[:16]

HKDF_INFO_BODY_SEED = b"stegx/v3/body-shuffle-seed"

def _derive_body_seed(head_seed_int: int, header_salt: bytes, fingerprint: bytes) -> int:
    if len(header_salt) != 16:
        raise ValueError("header_salt must be exactly 16 bytes")
    prk = head_seed_int.to_bytes(8, "big").ljust(32, b"\x00")
    info = HKDF_INFO_BODY_SEED + b"\x00" + fingerprint + b"\x00" + header_salt
    return int.from_bytes(hkdf_subkey(prk, info, length=8), "big")

def _derive_position_material(
    password: str,
    keyfile_bytes: Optional[bytes],
    fingerprint: bytes,
    yubikey_response: Optional[bytes] = None,
) -> Tuple[int, bytes, int]:
    position_salt = _derive_position_salt(fingerprint)
    with SecureBuffer(
        data=derive_master_key(
            password,
            position_salt,
            _POSITION_KDF_PARAMS,
            keyfile_bytes,
            yubikey_response,


        )
    ) as position_key:
        seed_sub = hkdf_subkey(
            bytes(position_key), HKDF_INFO_SEED + fingerprint, length=8
        )
        decoy_sub = hkdf_subkey(
            bytes(position_key), HKDF_INFO_DECOY_SEED + fingerprint, length=8
        )
        sentinel_key = hkdf_subkey(
            bytes(position_key), HKDF_INFO_SENTINEL + fingerprint, length=32
        )
        return (
            seed_int_from_subkey(seed_sub),
            sentinel_key,
            seed_int_from_subkey(decoy_sub),
        )


@dataclass
class EmbedOptions:
    dual_cipher: bool = False
    use_matrix_embedding: bool = False
    use_adaptive: bool = False
    adaptive_cutoff: float = 0.40
    adaptive_cost_mode: str = emb.COST_LAPLACIAN
    max_fill_ratio: float = 1.0
    keyfile_bytes: Optional[bytes] = None
    yubikey_response: Optional[bytes] = None
    yk_challenge_nonce: Optional[bytes] = None
    decoy_file_bytes: Optional[bytes] = None
    decoy_filename: Optional[str] = None
    decoy_password: Optional[str] = None
    always_split_cover: bool = False
    panic_password: Optional[str] = None
    panic_marker_payload: Optional[bytes] = None
    preserve_cover_encoding: bool = True
    compression: bool = True
    kdf_params: KdfParams = None

    def __post_init__(self) -> None:
        if self.kdf_params is None:
            self.kdf_params = KdfParams.default_argon2id()


def _determine_method(options: EmbedOptions) -> str:
    if options.use_matrix_embedding:
        return MATRIX_HAMMING


    if options.use_adaptive:
        return LSB_REPLACEMENT
    return LSB_MATCHING

def _build_encrypt_options(
    options: EmbedOptions, flags_base: int = 0
) -> EncryptOptions:
    return EncryptOptions(
        kdf_params=options.kdf_params,
        dual_cipher=options.dual_cipher,
        keyfile_bytes=options.keyfile_bytes,
        yubikey_response=options.yubikey_response,
        yk_challenge_nonce=options.yk_challenge_nonce,
        base_flags=flags_base,
    )

def _capacity_check(
    embed_bytes: bytes,
    available_positions: int,
    options: EmbedOptions,
    label: str,
) -> None:

    head_bytes = _head_byte_count_from_embed(embed_bytes)
    head_bits = head_bytes * 8

    assert len(embed_bytes) >= head_bytes, (
        f"embed stream shorter than head ({len(embed_bytes)} < {head_bytes})"
    )
    body_bits = len(embed_bytes) * 8 - head_bits
    needed = head_bits + positions_needed(
        body_bits,
        _determine_method(options) if label == "real payload" else LSB_MATCHING,
    )
    if needed > available_positions:
        raise InsufficientCapacity(
            f"Insufficient capacity for {label}: need {needed} positions,"
            f" have {available_positions}."
        )
    fill = needed / max(available_positions, 1)
    if fill > options.max_fill_ratio:
        raise InsufficientCapacity(
            f"Payload uses {fill*100:.1f}% of {label} capacity, exceeding"
            f" --max-fill={options.max_fill_ratio*100:.0f}%."
        )

def _build_positions(
    region: List[Position],
    seed_int: int,
    image: Image.Image,
    options: EmbedOptions,
) -> List[Position]:
    ordered = reorder_region(region, seed_int)
    if options.use_adaptive:
        filtered = _apply_adaptive(
            ordered, image, options.adaptive_cutoff, options.adaptive_cost_mode
        )
        if filtered is not None:
            return filtered
        logging.debug(
            "Adaptive mask empty for this cover; using full shuffled position list."
        )
    return ordered


def _embed_stream(
    pixels,
    mode: str,
    head_positions: Sequence[Position],
    body_positions: Sequence[Position],
    embed_bytes: bytes,
    method_ct: str,
    fingerprint_tag: bytes,
    is_adaptive: bool = False,
) -> None:
    rng = random.Random(int.from_bytes(fingerprint_tag[:8], "big") ^ 0xA5A5A5A5)

    head_byte_count = _head_byte_count_from_embed(embed_bytes)

    head_bytes_data = embed_bytes[:head_byte_count]
    body_bytes_data = embed_bytes[head_byte_count:]
    head_bits = bytes_to_bits(head_bytes_data)
    body_bits = bytes_to_bits(body_bytes_data)


    head_method = LSB_REPLACEMENT if (method_ct == LSB_REPLACEMENT or is_adaptive) else LSB_MATCHING

    embed_bits(
        pixels=pixels,
        mode=mode,
        positions=head_positions[: len(head_bits)],
        bits=head_bits,
        method=head_method,
        rng=rng,
    )
    if body_bits:
        embed_bits(
            pixels=pixels,
            mode=mode,
            positions=body_positions[: positions_needed(len(body_bits), method_ct)],
            bits=body_bits,
            method=method_ct,
            rng=rng,
            use_replacement_for_matrix=is_adaptive,
        )

def _split_head_body(
    all_ordered: List[Position],
    embed_bytes: bytes,
    body_seed_int: Optional[int],
) -> Tuple[List[Position], List[Position]]:
    head_byte_count = _head_byte_count_from_embed(embed_bytes)
    head_bits_count = head_byte_count * 8

    if len(all_ordered) < head_bits_count:
        raise InsufficientCapacity(
            f"Adaptive mask left only {len(all_ordered)} positions; "
            f"need {head_bits_count} for sentinel+header (incl. kms_wrap)."
        )

    head_pos = all_ordered[:head_bits_count]
    body_pool = list(all_ordered[head_bits_count:])

    if body_seed_int is not None:
        random.Random(body_seed_int).shuffle(body_pool)

    return head_pos, body_pool


def embed_v2(
    cover_image_path: str,
    inner_plaintext: bytes,
    output_image_path: str,
    password: str,
    options: EmbedOptions,
) -> str:
    image = _open_cover(cover_image_path)
    try:
        if not output_image_path.lower().endswith(".png"):
            logging.warning("Output does not end with .png; appending .png.")
            output_image_path = os.path.splitext(output_image_path)[0] + ".png"

        fingerprint = cover_fingerprint(image)
        all_positions = _all_positions(image)

        has_decoy = bool(options.decoy_file_bytes and options.decoy_password)
        has_panic = bool(options.panic_password)
        split_cover = has_decoy or has_panic or options.always_split_cover
        if split_cover:
            decoy_region, real_region = split_regions(all_positions, fingerprint)
        else:
            decoy_region = []
            real_region = all_positions


        seed_int, sentinel_key, decoy_seed_int = _derive_position_material(
            password, options.keyfile_bytes, fingerprint
        )

        real_positions = _build_positions(real_region, seed_int, image, options)

        flags_base = 0
        if options.compression:
            from .header import FLAG_COMPRESSED
            flags_base |= FLAG_COMPRESSED
        if options.use_adaptive:
            flags_base |= FLAG_ADAPTIVE
        if options.use_matrix_embedding:
            flags_base |= FLAG_MATRIX


        real_encrypted_stream = encrypt_data(
            inner_plaintext,
            password,
            _build_encrypt_options(options, flags_base=flags_base),
        )


        gen_header = Header.unpack(real_encrypted_stream)
        body_seed: Optional[int] = None
        if gen_header.header_salt is not None:
            body_seed = _derive_body_seed(seed_int, gen_header.header_salt, fingerprint)

        sentinel = derive_sentinel(sentinel_key, fingerprint)
        real_embed_bytes = sentinel + real_encrypted_stream

        head_positions, body_positions = _split_head_body(
            real_positions, real_embed_bytes, body_seed
        )

        _capacity_check(
            real_embed_bytes,
            len(real_positions),
            options,
            label="real payload",
        )

        pixels = image.load()

        _embed_stream(
            pixels=pixels,
            mode=image.mode,
            head_positions=head_positions,
            body_positions=body_positions,
            embed_bytes=real_embed_bytes,
            method_ct=_determine_method(options),
            fingerprint_tag=fingerprint,
            is_adaptive=options.use_adaptive,
        )

        if has_decoy:
            _embed_decoy(
                image=image,
                pixels=pixels,
                decoy_region=decoy_region,
                fingerprint=fingerprint,
                options=options,
            )
        elif options.panic_password and decoy_region:
            _embed_panic(
                image=image,
                pixels=pixels,
                decoy_region=decoy_region,
                fingerprint=fingerprint,
                options=options,
            )
        elif options.always_split_cover and decoy_region:
            _fill_phantom_region(
                image=image,
                pixels=pixels,
                region=decoy_region,
                real_bytes_len=len(real_embed_bytes),
                fingerprint=fingerprint,
            )

        encoder_params = sniff_png_encoder(cover_image_path)
        save_as_stego_png(image, output_image_path, encoder_params, options.preserve_cover_encoding)

        logging.info(
            "StegX v3 embed: cover=%s out=%s payload=%d B adaptive=%s matrix=%s dual=%s decoy=%s",
            cover_image_path,
            output_image_path,
            len(inner_plaintext),
            options.use_adaptive,
            options.use_matrix_embedding,
            options.dual_cipher,
            has_decoy,
        )
        return output_image_path
    finally:
        image.close()


def _fill_phantom_region(
    image: Image.Image,
    pixels,
    region: Sequence[Position],
    real_bytes_len: int,
    fingerprint: bytes,
) -> None:
    if not region:
        return
    phantom_bytes_len = max(real_bytes_len, HEAD_BYTES_V3 + 32)
    phantom_bits_len = min(phantom_bytes_len * 8, len(region))

    phantom_seed = int.from_bytes(os.urandom(8), "big")
    phantom_positions = reorder_region(region, phantom_seed)[:phantom_bits_len]
    phantom_bytes = os.urandom((phantom_bits_len + 7) // 8)
    phantom_bits = bytes_to_bits(phantom_bytes)[:phantom_bits_len]

    rng = random.Random(int.from_bytes(fingerprint[:8], "big") ^ 0x5A5A5A5A)
    embed_bits(
        pixels=pixels,
        mode=image.mode,
        positions=phantom_positions,
        bits=phantom_bits,
        method=LSB_MATCHING,
        rng=rng,
    )
    logging.debug("Phantom decoy fill: %d random bits embedded.", phantom_bits_len)

def _embed_panic(
    image: Image.Image,
    pixels,
    decoy_region: Sequence[Position],
    fingerprint: bytes,
    options: EmbedOptions,
) -> None:
    from .panic import PANIC_MODE_DECOY, PANIC_MODE_SILENT, build_panic_payload

    if not options.panic_password:
        return

    sacrificial = options.panic_marker_payload or os.urandom(32)
    mode = PANIC_MODE_DECOY if options.panic_marker_payload else PANIC_MODE_SILENT
    compression_mode = _CX_MODE_BEST if options.compression else _CX_MODE_FAST
    inner_plaintext = build_panic_payload(sacrificial, "panic.dat", mode, compression_mode)

    panic_seed_int, panic_sentinel_key, _ = _derive_position_material(
        options.panic_password,
        options.keyfile_bytes,
        fingerprint,
    )
    panic_positions = reorder_region(decoy_region, panic_seed_int)

    panic_flags = 0
    if options.compression:
        from .header import FLAG_COMPRESSED
        panic_flags |= FLAG_COMPRESSED

    panic_ct = encrypt_data(
        inner_plaintext,
        options.panic_password,
        EncryptOptions(
            kdf_params=options.kdf_params,
            dual_cipher=False,
            keyfile_bytes=options.keyfile_bytes,
            yubikey_response=options.yubikey_response,
            base_flags=panic_flags,
        ),
    )

    gen_header = Header.unpack(panic_ct)
    panic_body_seed: Optional[int] = None
    if gen_header.header_salt is not None:
        panic_body_seed = _derive_body_seed(panic_seed_int, gen_header.header_salt, fingerprint)

    panic_sentinel = derive_sentinel(panic_sentinel_key, fingerprint)
    panic_bytes = panic_sentinel + panic_ct
    _capacity_check(panic_bytes, len(panic_positions), options, label="panic payload")

    head_pos, body_pos = _split_head_body(panic_positions, panic_bytes, panic_body_seed)
    _embed_stream(
        pixels=pixels,
        mode=image.mode,
        head_positions=head_pos,
        body_positions=body_pos,
        embed_bytes=panic_bytes,
        method_ct=LSB_MATCHING,
        fingerprint_tag=fingerprint + b"panic",
        is_adaptive=options.use_adaptive,
    )
    logging.debug("Panic payload embedded (mode=%s, size=%d B).", mode, len(sacrificial))

def _embed_decoy(
    image: Image.Image,
    pixels,
    decoy_region: Sequence[Position],
    fingerprint: bytes,
    options: EmbedOptions,
) -> None:
    from .utils import create_payload_from_bytes

    decoy_payload = create_payload_from_bytes(
        options.decoy_filename or "decoy.dat",
        options.decoy_file_bytes,
        compress=options.compression,
    )
    decoy_seed_int, decoy_sentinel_key, _ = _derive_position_material(
        options.decoy_password,
        options.keyfile_bytes,
        fingerprint,
    )
    decoy_positions = reorder_region(decoy_region, decoy_seed_int)

    decoy_flags = 0
    if options.compression:
        from .header import FLAG_COMPRESSED
        decoy_flags |= FLAG_COMPRESSED

    decoy_ct = encrypt_data(
        decoy_payload,
        options.decoy_password,
        EncryptOptions(
            kdf_params=options.kdf_params,
            dual_cipher=False,
            keyfile_bytes=options.keyfile_bytes,
            base_flags=decoy_flags,
        ),
    )

    gen_header = Header.unpack(decoy_ct)
    decoy_body_seed: Optional[int] = None
    if gen_header.header_salt is not None:
        decoy_body_seed = _derive_body_seed(decoy_seed_int, gen_header.header_salt, fingerprint)

    decoy_sentinel = derive_sentinel(decoy_sentinel_key, fingerprint)
    decoy_bytes = decoy_sentinel + decoy_ct
    _capacity_check(decoy_bytes, len(decoy_positions), options, label="decoy payload")

    head_pos, body_pos = _split_head_body(decoy_positions, decoy_bytes, decoy_body_seed)
    _embed_stream(
        pixels=pixels,
        mode=image.mode,
        head_positions=head_pos,
        body_positions=body_pos,
        embed_bytes=decoy_bytes,
        method_ct=LSB_MATCHING,
        fingerprint_tag=fingerprint + b"decoy",
        is_adaptive=options.use_adaptive,
    )


def extract_v2(
    stego_image_path: str,
    password: str,
    keyfile_bytes: Optional[bytes] = None,
    try_adaptive_fallback: bool = True,
    yubikey_response: Optional[bytes] = None,
    yubikey_factory: Optional[Callable[[bytes], bytes]] = None,
    allow_v1: bool = False,
) -> bytes:
    data, _region = extract_v2_with_region(
        stego_image_path,
        password,
        keyfile_bytes,
        try_adaptive_fallback=try_adaptive_fallback,
        yubikey_response=yubikey_response,
        yubikey_factory=yubikey_factory,
        allow_v1=allow_v1,
    )
    return data

def extract_v2_with_region(
    stego_image_path: str,
    password: str,
    keyfile_bytes: Optional[bytes] = None,
    try_adaptive_fallback: bool = True,
    yubikey_response: Optional[bytes] = None,
    yubikey_factory: Optional[Callable[[bytes], bytes]] = None,
    allow_v1: bool = False,
) -> Tuple[bytes, str]:
    if not os.path.exists(stego_image_path):
        raise FileNotFoundError(f"Stego image not found: {stego_image_path}")

    image = Image.open(stego_image_path)
    try:
        if image.mode == "P":
            image = image.convert("RGBA")
        if image.mode not in ("RGB", "RGBA", "L"):
            raise UnsupportedImageMode(f"Unsupported image mode: {image.mode}.")

        fingerprint = cover_fingerprint(image)
        all_positions = _all_positions(image)


        seed_int, sentinel_key, _ = _derive_position_material(
            password, keyfile_bytes, fingerprint, yubikey_response
        )
        expected_sentinel = derive_sentinel(sentinel_key, fingerprint)

        for region_name, region in _candidate_regions(all_positions, fingerprint):
            ordered = reorder_region(region, seed_int)
            candidate_lists: List[List[Position]] = [ordered]
            if try_adaptive_fallback:
                for cost_mode in (emb.COST_LAPLACIAN, emb.COST_HILL):
                    try:
                        filtered = _apply_adaptive(
                            ordered, image, cutoff=0.40, cost_mode=cost_mode
                        )
                        if filtered is not None:
                            candidate_lists.append(filtered)
                    except Exception as e:
                        logging.debug("adaptive mode %s failed: %s", cost_mode, e)

            for positions in candidate_lists:
                try:
                    data = _read_and_decrypt(
                        image=image,
                        positions=positions,
                        expected_sentinel=expected_sentinel,
                        password=password,
                        keyfile_bytes=keyfile_bytes,
                        yubikey_response=yubikey_response,
                        yubikey_factory=yubikey_factory,
                        fingerprint=fingerprint,
                        head_seed_int=seed_int,
                    )
                    return data, region_name
                except _SentinelMismatch:
                    logging.debug(
                        "Sentinel mismatch in region %s; trying next.", region_name
                    )
                    continue
                except ValueError as e:
                    logging.debug(
                        "Candidate in region %s passed sentinel but failed (%s); "
                        "trying next.",
                        region_name, e,
                    )
                    continue

        if allow_v1:
            try:
                legacy = _try_extract_legacy_v1(image, password)
                logging.warning(
                    "Decoded legacy v1 payload. Re-encode to v3 — v1 is weaker."
                )
                return legacy, "legacy-v1"
            except Exception as legacy_exc:
                logging.debug("Legacy v1 extraction failed: %s", legacy_exc)
        else:
            logging.debug("Legacy v1 decode skipped (not enabled).")

        raise ValueError(
            "Extraction failed: wrong password, wrong keyfile, or image does not"
            " contain StegX data."
        )
    finally:
        image.close()


def _candidate_regions(
    all_positions: Sequence[Position], fingerprint: bytes
) -> List[Tuple[str, List[Position]]]:
    decoy_region, real_region = split_regions(all_positions, fingerprint)
    return [
        ("real-full", list(all_positions)),
        ("real-half", real_region),
        ("decoy-half", decoy_region),
    ]


class _SentinelMismatch(Exception):
    pass

def _read_and_decrypt(
    image: Image.Image,
    positions: Sequence[Position],
    expected_sentinel: bytes,
    password: str,
    keyfile_bytes: Optional[bytes],
    yubikey_response: Optional[bytes] = None,
    yubikey_factory: Optional[Callable[[bytes], bytes]] = None,
    fingerprint: bytes = b"",
    head_seed_int: int = 0,
) -> bytes:
    pixels = image.load()
    mode = image.mode

    if len(positions) < SENTINEL_BITS:
        raise _SentinelMismatch()


    sentinel_bits = extract_bits(
        pixels, mode, positions[:SENTINEL_BITS], SENTINEL_BITS, LSB_REPLACEMENT
    )
    if not bits_match_sentinel(sentinel_bits, expected_sentinel):
        raise _SentinelMismatch()


    base_peek_bits = _HEAD_PEEK_BYTES * 8
    if len(positions) < SENTINEL_BITS + base_peek_bits:
        raise CorruptedPayload("Insufficient positions for header peek.")

    raw_base_bits = extract_bits(
        pixels,
        mode,
        positions[SENTINEL_BITS : SENTINEL_BITS + base_peek_bits],
        base_peek_bits,
        LSB_REPLACEMENT,
    )
    raw_base_bytes = bits_to_bytes(raw_base_bits)

    version = raw_base_bytes[1]

    if version == 0x02:
        header_bytes = raw_base_bytes[:HEADER_SIZE_V2]
        body_start = SENTINEL_BITS + HEADER_SIZE_V2 * 8

    elif version == 0x03:


        kms_wrap_len = int.from_bytes(raw_base_bytes[88:90], "big")
        if kms_wrap_len > KMS_WRAP_MAX:
            raise CorruptedPayload(
                f"kms_wrap_len {kms_wrap_len} exceeds maximum {KMS_WRAP_MAX}."
            )
        full_header_bits = (HEADER_SIZE_V3_BASE + kms_wrap_len) * 8
        body_start = SENTINEL_BITS + full_header_bits

        if kms_wrap_len == 0:
            header_bytes = raw_base_bytes[:HEADER_SIZE_V3_BASE]
        else:

            wrap_start = SENTINEL_BITS + HEADER_SIZE_V3_BASE * 8
            wrap_end   = SENTINEL_BITS + full_header_bits
            if len(positions) < wrap_end:
                raise CorruptedPayload("Insufficient positions for KMS wrap data.")
            wrap_bits = extract_bits(
                pixels, mode,
                positions[wrap_start:wrap_end],
                kms_wrap_len * 8,
                LSB_REPLACEMENT,
            )
            header_bytes = raw_base_bytes[:HEADER_SIZE_V3_BASE] + bits_to_bytes(wrap_bits)

    else:
        raise ValueError(f"Unsupported header version: 0x{version:02x}")

    try:
        header = Header.unpack(header_bytes)
    except Exception as exc:
        raise ValueError(f"Header parse failed: {exc}") from exc


    body_remaining = list(positions[body_start:])

    if header.header_salt is not None:

        body_seed = _derive_body_seed(head_seed_int, header.header_salt, fingerprint)
        random.Random(body_seed).shuffle(body_remaining)


    active_yk_response = yubikey_response
    if header.has(FLAG_YUBIKEY) and yubikey_factory is not None:
        if header.header_salt is not None:
            from .yubikey import challenge_for_operation
            nonce = header.yk_challenge_nonce or b"\x00" * YK_CHALLENGE_NONCE_LEN
            challenge = challenge_for_operation(nonce, fingerprint)
        else:
            challenge = hashlib.sha256(
                b"stegx/v2/yubikey-challenge\x00" + fingerprint
            ).digest()[:32]
        active_yk_response = yubikey_factory(challenge)


    ct_len_bits = header.inner_ct_length * 8
    ct_method = MATRIX_HAMMING if header.has(FLAG_MATRIX) else LSB_REPLACEMENT
    ct_positions_needed = positions_needed(ct_len_bits, ct_method)

    if len(body_remaining) < ct_positions_needed:
        raise CorruptedPayload("Insufficient positions for ciphertext.")

    ct_bits = extract_bits(
        pixels,
        mode,
        body_remaining[:ct_positions_needed],
        ct_len_bits,
        ct_method,
    )
    ciphertext = bits_to_bytes(ct_bits)

    full_encrypted = header_bytes + ciphertext
    try:
        return decrypt_data(full_encrypted, password, keyfile_bytes, active_yk_response)
    except InvalidTag:
        raise ValueError(
            "Extraction failed: wrong password, wrong keyfile, or image does not"
            " contain StegX data."
        )


def _try_extract_legacy_v1(image: Image.Image, password: str) -> bytes:
    seed_int = derive_legacy_seed_from_password(password)
    all_positions = _all_positions(image)
    positions = _shuffle_positions(all_positions, seed_int)

    pixels = image.load()
    mode = image.mode

    extracted: List[str] = []
    buf = ""
    sentinel_str = "".join(format(b, "08b") for b in DATA_SENTINEL)


    for x, y, c in positions:
        lsb = (pixels[x, y][c] if mode in ("RGB", "RGBA") else pixels[x, y]) & 1
        extracted.append(str(lsb))
        buf += str(lsb)
        if len(buf) > SENTINEL_LENGTH_BITS:
            buf = buf[1:]
        if len(buf) == SENTINEL_LENGTH_BITS and buf == sentinel_str:
            data_bits = "".join(extracted[:-SENTINEL_LENGTH_BITS])
            encrypted = bits_to_bytes(data_bits)
            return decrypt_legacy_v1(encrypted, password)

    raise ValueError("Legacy v1 sentinel not found.")


def embed_data(
    cover_image_path: str,
    data_to_hide: bytes,
    output_image_path: str,
    password: str,
) -> bool:
    options = EmbedOptions()
    embed_v2(cover_image_path, data_to_hide, output_image_path, password, options)
    return True

def extract_data(stego_image_path: str, password: str) -> bytes:
    return extract_v2(stego_image_path, password)

def get_seed_from_password(password: str) -> int:
    return derive_legacy_seed_from_password(password)

def generate_pixel_positions(width: int, height: int, channels: int, password: str):
    seed_int = derive_legacy_seed_from_password(password)
    positions: List[Position] = []
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                positions.append((x, y, c))
    random.Random(seed_int).shuffle(positions)
    return positions

__all__ = [
    "EmbedOptions",
    "calculate_lsb_capacity",
    "embed_data",
    "embed_v2",
    "extract_data",
    "extract_v2",
    "extract_v2_with_region",
    "generate_pixel_positions",
    "get_seed_from_password",
]
