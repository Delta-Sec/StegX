import io
import json
import logging
import os
import re
import tarfile
import zlib
from typing import List, Optional, Tuple

from . import compression as _cx
from .constants import MAX_BUNDLE_MEMBERS, MAX_BUNDLE_TOTAL_BYTES
from .exceptions import CorruptedPayload, EmptyPayloadError, TarExtractionError
from .safe_paths import PathValidationError, ensure_under_base, sink_safe_path

META_VERSION = "version"
META_FILENAME = "filename"
META_ORIG_SIZE = "original_size"
META_COMPRESSED = "compressed"
META_COMPRESSION_ALG = "compression_alg"
META_BUNDLE_FORMAT = "bundle_format"
META_PANIC = "panic"
META_PANIC_MODE = "panic_mode"
BUNDLE_FORMAT_TAR = "tar"

CURRENT_META_VERSION = 3

def setup_logging(level=logging.INFO):
    logger = logging.getLogger("stegx")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - [%(module)s] - %(message)s")
        )
        logger.addHandler(handler)
        logger.propagate = False

def compress_data(data: bytes) -> bytes:
    return zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)

def decompress_data(compressed_data: bytes) -> bytes:
    return zlib.decompress(compressed_data)

def _bundle_files_to_tar(paths: List[str]) -> Tuple[str, bytes]:
    if not paths:
        raise ValueError("Cannot bundle zero files.")
    total_bytes = 0
    buf = io.BytesIO()

    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path in paths:
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Bundle member not found: {path}")
            total_bytes += os.path.getsize(path)
            arcname = os.path.basename(path) or "file.dat"
            tar.add(path, arcname=arcname, recursive=False)
    if total_bytes == 0:
        raise EmptyPayloadError(
            "Refusing to embed bundle: every member is zero bytes."
        )
    display = "stegx_bundle.tar" if len(paths) > 1 else os.path.basename(paths[0])
    return display, buf.getvalue()

def create_payload_from_files(
    paths: List[str],
    compress: bool = True,
    compression_mode: str = _cx.MODE_BEST,
    show_progress: bool = False,
) -> bytes:
    if not paths:
        raise ValueError("Need at least one file to create a payload.")
    if len(paths) == 1:
        return create_payload(paths[0], compress=compress,
                              compression_mode=compression_mode,
                              show_progress=show_progress)

    display_name, tar_bytes = _bundle_files_to_tar(paths)
    return create_payload_from_bytes(
        display_name,
        tar_bytes,
        compress=compress,
        compression_mode=compression_mode,
        show_progress=show_progress,
        bundle_format=BUNDLE_FORMAT_TAR,
    )

def create_payload_from_bytes(
    filename: str,
    original_data: bytes,
    compress: bool = True,
    compression_mode: str = _cx.MODE_BEST,
    show_progress: bool = False,
    bundle_format: Optional[str] = None,
    panic: bool = False,
    panic_mode: Optional[str] = None,
) -> bytes:
    original_size = len(original_data)
    if original_size == 0:


        raise EmptyPayloadError(
            f"Refusing to embed empty payload {filename!r}: nothing to hide."
        )
    file_data = original_data
    is_compressed = False
    alg_name = _cx.ALG_NONE

    if compress and original_data:
        winner_alg, winner_blob = _cx.compress_best(
            original_data, mode=compression_mode, show_progress=show_progress
        )
        if winner_alg != _cx.ALG_NONE and len(winner_blob) < original_size:
            file_data = winner_blob
            is_compressed = True
            alg_name = winner_alg
            logging.info(
                "Compression: %s",
                _cx.ratio_report(original_size, len(winner_blob)) + f" via {winner_alg}",
            )
        else:
            logging.info("Compression attempted but original was smaller — storing raw.")

    metadata = {
        META_VERSION: CURRENT_META_VERSION,
        META_FILENAME: os.path.basename(filename) or "payload.dat",
        META_ORIG_SIZE: original_size,
        META_COMPRESSED: is_compressed,
        META_COMPRESSION_ALG: alg_name,
    }
    if bundle_format:
        metadata[META_BUNDLE_FORMAT] = bundle_format
    if panic:
        metadata[META_PANIC] = True
        if panic_mode:
            metadata[META_PANIC_MODE] = panic_mode
    metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    metadata_len_bytes = len(metadata_bytes).to_bytes(4, byteorder="little")
    return metadata_len_bytes + metadata_bytes + file_data

def create_payload(
    file_path: str,
    compress: bool = True,
    compression_mode: str = _cx.MODE_BEST,
    show_progress: bool = False,
) -> bytes:

    logging.info(
        "Creating payload for file: %s, Compression: %s (mode=%s)",
        file_path, compress, compression_mode,
    )
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")

    try:
        with open(file_path, "rb") as f:
            original_data = f.read()
        filename = os.path.basename(file_path)

        logging.debug("Read file '%s' Size: %d bytes", filename, len(original_data))
        payload = create_payload_from_bytes(
            filename,
            original_data,
            compress=compress,
            compression_mode=compression_mode,
            show_progress=show_progress,
        )
        logging.info("Total payload size created: %d bytes", len(payload))
        return payload

    except FileNotFoundError:
        logging.error("File not found during payload creation: %s", file_path)
        raise
    except IOError as e:
        logging.error("IOError reading file %s: %s", file_path, e)
        raise
    except Exception as e:
        logging.exception("Error creating payload for %s: %s", file_path, e)
        raise

def parse_payload(payload: bytes) -> Tuple[str, bytes]:
    name, data, _meta = parse_payload_full(payload)
    return name, data


_ALLOW_FUTURE_META_VERSION: bool = False

def allow_future_meta_version(allow: bool) -> None:
    global _ALLOW_FUTURE_META_VERSION
    _ALLOW_FUTURE_META_VERSION = bool(allow)

def parse_payload_full(
    payload: bytes,
    *,
    allow_future_version: Optional[bool] = None,
) -> Tuple[str, bytes, dict]:

    logging.info("Parsing payload of size: %d bytes", len(payload))
    if len(payload) < 4:
        raise CorruptedPayload("Invalid payload: Too short to contain metadata length.")

    try:
        metadata_len = int.from_bytes(payload[:4], byteorder="little")
        logging.debug("Expected metadata length: %d bytes", metadata_len)

        if len(payload) < 4 + metadata_len:
            raise CorruptedPayload("Invalid payload: Too short to contain metadata.")

        metadata_bytes = payload[4: 4 + metadata_len]
        file_data = payload[4 + metadata_len:]
        logging.debug("Actual metadata bytes length: %d", len(metadata_bytes))
        logging.debug("File data length: %d", len(file_data))

        metadata = json.loads(metadata_bytes.decode("utf-8"))
        logging.debug("Parsed metadata (JSON): %s", metadata)

        if not all(k in metadata for k in [META_VERSION, META_FILENAME, META_ORIG_SIZE, META_COMPRESSED]):
            raise CorruptedPayload("Invalid metadata: Missing required keys.")

        if metadata[META_VERSION] > CURRENT_META_VERSION:


            allow = (
                _ALLOW_FUTURE_META_VERSION
                if allow_future_version is None
                else bool(allow_future_version)
            )
            if not allow:
                raise CorruptedPayload(
                    f"Payload metadata version {metadata[META_VERSION]} is newer "
                    f"than supported ({CURRENT_META_VERSION}). Upgrade StegX, or "
                    f"pass allow_future_version=True to parse_payload_full to opt "
                    f"in to lossy forward-compatible parsing."
                )
            logging.warning(
                "Payload metadata version (%s) is newer than supported (%s). Attempting to parse anyway.",
                metadata[META_VERSION], CURRENT_META_VERSION,
            )

        filename = metadata[META_FILENAME]
        is_compressed = metadata[META_COMPRESSED]
        original_size = metadata[META_ORIG_SIZE]

        if not filename or not isinstance(filename, str):
            raise CorruptedPayload("Invalid metadata: Filename is missing or invalid.")

        if is_compressed:
            alg = metadata.get(META_COMPRESSION_ALG, _cx.ALG_ZLIB)
            logging.info("Decompressing file data for '%s' via %s", filename, alg)
            try:
                decompressed_data = _cx.decompress(alg, file_data)
                if len(decompressed_data) != original_size:
                    logging.warning(
                        "Decompressed size (%d) does not match original size (%d) "
                        "stored in metadata for '%s'. Using decompressed data.",
                        len(decompressed_data), original_size, filename,
                    )
                final_data = decompressed_data
            except (zlib.error, ValueError, OSError) as e:
                logging.error("Decompression failed for %s: %s", filename, e)
                raise CorruptedPayload(f"Failed to decompress data: {e}")
            except Exception as e:
                logging.error("Decompression failed for %s: %s", filename, e)
                raise CorruptedPayload(f"Failed to decompress data: {e}")
        else:

            logging.info("File data for %s was not compressed.", filename)
            if len(file_data) != original_size:
                logging.warning(
                    "Stored data size (%d) does not match original size (%d) "
                    "stored in metadata for %s. Using stored data.",
                    len(file_data), original_size, filename,
                )
            final_data = file_data

        logging.info(
            "Successfully parsed payload. Extracted file: %s Size: %d bytes",
            filename, len(final_data),
        )
        return filename, final_data, metadata

    except json.JSONDecodeError as e:
        logging.error("Failed to decode metadata JSON: %s", e)
        raise CorruptedPayload(f"Invalid metadata format: {e}")
    except ValueError as e:
        logging.error("Payload parsing error: %s", e)
        raise
    except Exception as e:
        logging.exception("Unexpected error during payload parsing: %s", e)
        raise

def save_extracted(
    filename: str,
    data: bytes,
    metadata: dict,
    output_dir: str,
) -> List[str]:
    if metadata.get(META_BUNDLE_FORMAT) == BUNDLE_FORMAT_TAR:
        return _extract_tar_bundle(data, output_dir)
    return [save_extracted_file(filename, data, output_dir)]

def _is_member_safe(member: tarfile.TarInfo, output_dir: str) -> bool:
    if not member.isfile() and not member.isdir():
        return False
    if member.issym() or member.islnk():
        return False
    name = member.name
    if not name or name.startswith(("/", "\\")):
        return False
    if ".." in name.replace("\\", "/").split("/"):
        return False
    resolved = os.path.realpath(os.path.join(output_dir, name))
    base = os.path.realpath(output_dir)
    return resolved == base or resolved.startswith(base + os.sep)

def _extract_tar_bundle(data: bytes, output_dir: str) -> List[str]:
    safe_output_dir = sink_safe_path(output_dir)
    os.makedirs(safe_output_dir, exist_ok=True)
    extracted: List[str] = []
    member_count = 0
    declared_total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        while True:
            member = tar.next()
            if member is None:
                break
            member_count += 1
            if member_count > MAX_BUNDLE_MEMBERS:
                raise TarExtractionError(
                    f"Tar bundle exceeds member cap ({MAX_BUNDLE_MEMBERS})."
                )


            declared_total += max(int(member.size), 0)
            if declared_total > MAX_BUNDLE_TOTAL_BYTES:
                raise TarExtractionError(
                    f"Tar bundle exceeds aggregate-size cap "
                    f"({MAX_BUNDLE_TOTAL_BYTES} bytes)."
                )
            if not _is_member_safe(member, safe_output_dir):
                logging.warning("Skipping unsafe tar member: %s", member.name)
                continue


            try:
                ensure_under_base(
                    os.path.join(safe_output_dir, member.name),
                    safe_output_dir,
                )
            except PathValidationError as escape:
                logging.warning(
                    "Refusing tar member that would escape %s: %s (%s)",
                    safe_output_dir, member.name, escape,
                )
                continue


            tar.extract(
                member,
                path=safe_output_dir,
                set_attrs=False,
                filter="data",
            )


            if member.isfile():
                extracted.append(os.path.join(safe_output_dir, member.name))
    logging.info(
        "Extracted %d files from bundle into %s (of %d members scanned)",
        len(extracted), safe_output_dir, member_count,
    )
    return extracted

def save_extracted_file(filename: str, data: bytes, output_dir: str):

    if not os.path.isdir(output_dir):
        logging.error("Output directory does not exist: %s", output_dir)
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    safe_filename = sanitize_filename(filename)
    if not safe_filename or safe_filename in (".", ".."):
        safe_filename = "extracted_file.dat"
        logging.warning(
            "Original filename %s was unsafe or empty. Saving as %s",
            filename, safe_filename,
        )

    output_path = os.path.join(output_dir, safe_filename)

    resolved = os.path.abspath(output_path)
    base = os.path.abspath(output_dir)
    if resolved != base and not resolved.startswith(base + os.sep):
        raise ValueError(
            f"Refusing to write outside output directory: {output_path}"
        )

    try:
        with open(output_path, "wb") as f:
            f.write(data)
        logging.info("Extracted file saved successfully to: %s", output_path)
        return output_path
    except IOError as e:
        logging.error("Failed to write extracted file %s: %s", output_path, e)
        raise IOError(f"Could not save extracted file: {e}")
    except Exception as e:
        logging.exception("Unexpected error saving file %s: %s", output_path, e)
        raise

def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename or "")
    safe_name = re.sub(r"[^\w.\-]", "_", base)

    safe_name = re.sub(r"\.{2,}", ".", safe_name).strip(".")
    return safe_name or "extracted_file.dat"
