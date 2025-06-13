import os
import re
import zlib
import json
import logging
from typing import Tuple

META_VERSION = "version"
META_FILENAME = "filename"
META_ORIG_SIZE = "original_size"
META_COMPRESSED = "compressed"

CURRENT_META_VERSION = 1

def setup_logging(level=logging.INFO):
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - [%(module)s] - %(message)s")

def compress_data(data: bytes) -> bytes:
    return zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)

def decompress_data(compressed_data: bytes) -> bytes:
    return zlib.decompress(compressed_data)

def create_payload(file_path: str, compress: bool = True) -> bytes:

    logging.info(f"Creating payload for file: {file_path}, Compression: {compress}")
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")

    try:
        with open(file_path, "rb") as f:
            original_data = f.read()
        original_size = len(original_data)
        filename = os.path.basename(file_path)

        logging.debug(f"Read file '{filename}' Size: {original_size} bytes")
        file_data = original_data
        is_compressed = False
        if compress:
            compressed_data = compress_data(original_data)
            if len(compressed_data) < original_size:
                file_data = compressed_data
                is_compressed = True
                logging.info(f"Compression enabled and effective: {original_size} -> {len(file_data)} bytes")
            else:
                logging.info("Compression enabled but not effective (size increased or stayed same) Using original data"
                             )
        else:
            logging.info("Compression disabled.")

        metadata = {
            META_VERSION: CURRENT_META_VERSION,
            META_FILENAME: filename,
            META_ORIG_SIZE: original_size,
            META_COMPRESSED: is_compressed
        }

        metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode("utf-8")

        metadata_len_bytes = len(metadata_bytes).to_bytes(4, byteorder="little")

        payload = metadata_len_bytes + metadata_bytes + file_data
        logging.debug(f"Metadata (JSON): {metadata}")
        logging.debug(f"Metadata size: {len(metadata_bytes)} bytes")
        logging.debug(f"File data size in payload: {len(file_data)} bytes")
        logging.info(f"Total payload size created: {len(payload)} bytes")

        return payload

    except FileNotFoundError:
        logging.error(f"File not found during payload creation: {file_path}")
        raise
    except IOError as e:
        logging.error(f"IOError reading file {file_path}: {e}")
        raise
    except Exception as e:
        logging.exception(f"Error creating payload for {file_path}: {e}")
        raise

def parse_payload(payload: bytes) -> Tuple[str, bytes]:

    logging.info(f"Parsing payload of size: {len(payload)} bytes")
    if len(payload) < 4:
        raise ValueError("Invalid payload: Too short to contain metadata length.")


    try:
        metadata_len = int.from_bytes(payload[:4], byteorder="little")
        logging.debug(f"Expected metadata length: {metadata_len} bytes")

        if len(payload) < 4 + metadata_len:
            raise ValueError("Invalid payload: Too short to contain metadata.")

        metadata_bytes = payload[4: 4 + metadata_len]
        file_data = payload[4 + metadata_len:]
        logging.debug(f"Actual metadata bytes length: {len(metadata_bytes)}")
        logging.debug(f"File data length: {len(file_data)}")

        metadata = json.loads(metadata_bytes.decode("utf-8"))
        logging.debug(f"Parsed metadata (JSON): {metadata}")


        if not all(k in metadata for k in [META_VERSION, META_FILENAME, META_ORIG_SIZE, META_COMPRESSED]):
            raise ValueError("Invalid metadata: Missing required keys.")

        if metadata[META_VERSION] > CURRENT_META_VERSION:
            logging.warning(f"Payload metadata version ({metadata[META_VERSION]}) is newer than supported "
                            f"({CURRENT_META_VERSION}). Attempting to parse anyway.")

        filename = metadata[META_FILENAME]
        is_compressed = metadata[META_COMPRESSED]
        original_size = metadata[META_ORIG_SIZE]

        if not filename or not isinstance(filename, str):
            raise ValueError("Invalid metadata: Filename is missing or invalid.")

        if is_compressed:
            logging.info(f"Decompressing file data for: {filename}")
            try:
                decompressed_data = decompress_data(file_data)
                if len(decompressed_data) != original_size:

                    logging.warning(f"Decompressed size ({len(decompressed_data)}) does not match original size"
                                    f"({original_size}) stored in metadata for '{filename}'. Using decompressed data.")
                final_data = decompressed_data
            except zlib.error as e:
                logging.error(f"Decompression failed for {filename}: {e}")
                raise ValueError(f"Failed to decompress data: {e}")
        else:

            logging.info(f"File data for  {filename} was not compressed.")
            if len(file_data) != original_size:
                logging.warning(f"Stored data size ({len(file_data)}) does not match original size ({original_size})"
                                f" stored in metadata for ", {filename}, " Using stored data.")
            final_data = file_data


        logging.info(f"Successfully parsed payload. Extracted file: {filename} Size: {len(final_data)} bytes")
        return filename, final_data

    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode metadata JSON: {e}")
        raise ValueError(f"Invalid metadata format: {e}")
    except ValueError as e:
        logging.error(f"Payload parsing error: {e}")
        raise
    except Exception as e:
        logging.exception(f"Unexpected error during payload parsing: {e}")
        raise

def save_extracted_file(filename: str, data: bytes, output_dir: str):

    if not os.path.isdir(output_dir):
        logging.error(f"Output directory does not exist: {output_dir}")
        raise FileNotFoundError(f"Output directory not found: {output_dir}")


    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename in (".", ".."):
        safe_filename = "extracted_file.dat"

        logging.warning(f"Original filename  {filename} was unsafe or empty. Saving as  {safe_filename}")

    output_path = os.path.join(output_dir, safe_filename)

    try:
        with open(output_path, "wb") as f:
            f.write(data)
        logging.info(f"Extracted file saved successfully to: {output_path}")
        return output_path
    except IOError as e:
        logging.error(f"Failed to write extracted file {output_path}: {e}")
        raise IOError(f"Could not save extracted file: {e}")
    except Exception as e:
        logging.exception(f"Unexpected error saving file {output_path}: {e}")
        raise
def sanitize_filename(filename: str) -> str:
    safe_name = re.sub(r'[^\w.-]', '_', os.path.basename(filename))

    if os.path.isdir(filename):
        raise ValueError(f"Path is a directory: {filename}")
    
    return safe_name
