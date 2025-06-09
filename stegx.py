import argparse
import os
import sys
import logging
from PIL import Image, UnidentifiedImageError
from cryptography.exceptions import InvalidTag
import zlib

from stegx_core.steganography import (
    calculate_lsb_capacity,
    embed_data as embed_core,
    extract_data as extract_core,
    bytes_to_bits_iterator,
    SENTINEL_LENGTH_BITS
)
from stegx_core.crypto import encrypt_data, decrypt_data, SALT_SIZE, NONCE_SIZE
from stegx_core.utils import (
    setup_logging,
    create_payload,
    parse_payload,
    save_extracted_file
)

__version__ = "1.0.0"
AES_GCM_TAG_SIZE = 16


def print_error(message):

    print(f"Error: {message}", file=sys.stderr)

def print_success(message):

    print(message)


def perform_encode(cover_image_path: str, file_to_hide_path: str, output_image_path: str, password: str, compress: bool):

    logging.info(f"Starting encoding process...")
    logging.info(f"Cover Image: {cover_image_path}")
    logging.info(f"File to Hide: {file_to_hide_path}")
    logging.info(f"Output Image: {output_image_path}")
    logging.info(f"Compression: {compress}")

    try:

        try:

            with Image.open(cover_image_path) as img_check:
                original_mode = img_check.mode

                img_copy = img_check.copy()
                if img_copy.mode == 'P':
                    logging.info(f"Converting image mode from {img_copy.mode} to RGBA for capacity check.")
                    img_check_converted = img_copy.convert("RGBA")
                elif img_copy.mode not in ('RGB', 'RGBA', 'L'):
                    raise ValueError(f"Unsupported cover image mode: {original_mode} Must be RGB,RGBA L,or P (Palette)")
                else:
                    img_check_converted = img_copy

                capacity_bits = calculate_lsb_capacity(img_check_converted)
                logging.info(f"Image capacity (excluding sentinel): {capacity_bits} bits ({capacity_bits // 8} bytes)")
                if capacity_bits <= 0:
                    raise ValueError("Image has zero or negative capacity for data embedding after accounting for sentinel.")

        except FileNotFoundError:
            raise
        except UnidentifiedImageError:
            raise ValueError(f"Cannot identify image file. Is \"{cover_image_path}\" a valid image?")
        except Exception as e:
            raise ValueError(f"Failed to open or process cover image \"{cover_image_path}\": {e}")

        payload_bytes = create_payload(file_to_hide_path, compress)


        logging.info("Encrypting payload...")
        encrypted_payload = encrypt_data(payload_bytes, password)
        encrypted_bits_len = len(encrypted_payload) * 8
        logging.info(f"Encrypted payload size: {len(encrypted_payload)} bytes ({encrypted_bits_len} bits)")

        if encrypted_bits_len > capacity_bits:
            raise ValueError(
                f"Insufficient image capacity. Required bits for encrypted data: {encrypted_bits_len}, "
                f"Available bits (excluding sentinel): {capacity_bits}. Try a larger image or disable compression if enabled."
            )

        logging.info("Embedding encrypted data into image LSBs...")
        embed_core(cover_image_path, encrypted_payload, output_image_path)
        print_success(f"Successfully encoded '{os.path.basename(file_to_hide_path)}' into '{output_image_path}'.")
        return True

    except (FileNotFoundError, ValueError, IOError, TypeError, zlib.error) as e:
        logging.error(f"Encoding failed: {e}")
        print_error(f"Encoding failed: {e}")
        return False
    except Exception as e:
        logging.exception("An unexpected error occurred during encoding:")
        print_error(f"An unexpected error occurred during encoding: {e}")
        return False

def perform_decode(stego_image_path: str, output_dir_path: str, password: str):

    logging.info(f"Starting decoding process...")
    logging.info(f"Stego Image: {stego_image_path}")
    logging.info(f"Output Directory: {output_dir_path}")

    try:

        logging.info("Extracting raw data from image LSBs...")
        extracted_encrypted_payload = extract_core(stego_image_path)
        if not extracted_encrypted_payload:
            raise ValueError("Extraction yielded no data.")
        logging.info(f"Extracted raw payload size: {len(extracted_encrypted_payload)} bytes")


        logging.info("Decrypting extracted data...")
        decrypted_payload = decrypt_data(extracted_encrypted_payload, password)
        logging.info(f"Decrypted payload size: {len(decrypted_payload)} bytes")

        logging.info("Parsing decrypted payload...")
        filename, file_data = parse_payload(decrypted_payload)


        logging.info(f"Saving extracted file as '{filename}' in '{output_dir_path}'...")
        output_path = save_extracted_file(filename, file_data, output_dir_path)

        print_success(f"Successfully decoded and saved file as '{output_path}'.")
        return True

    except InvalidTag:
        logging.error("Decryption failed: Invalid authentication tag. Password likely incorrect or data corrupted.")
        print_error("Decryption failed. The password might be incorrect, or the image data is corrupted.")
        return False
    except (FileNotFoundError, ValueError, IOError, TypeError, zlib.error) as e:
        logging.error(f"Decoding failed: {e}")

        if "sentinel not found" in str(e).lower():
            print_error("Decoding failed: Could not find hidden data marker in the image. Is this a valid StegX image?")
        elif "payload" in str(e).lower() or "metadata" in str(e).lower():
            print_error(f"Decoding failed: Payload or metadata seems corrupted. {e}")
        else:
            print_error(f"Decoding failed: {e}")
        return False
    except Exception as e:
        logging.exception("An unexpected error occurred during decoding:")
        print_error(f"An unexpected error occurred during decoding: {e}")
        return False


def main():
    """Main function to handle command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"StegX v{__version__}: Hide files in images using LSB steganography and AES encryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example usage:\n"
               "  stegx encode -i cover.png -f secret.zip -o stego.png -p MyPassword123\n"
               "  stegx decode -i stego.png -d ./extracted_files -p MyPassword123"
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose debug logging."
    )

    subparsers = parser.add_subparsers(dest="mode", required=True, help="Available modes: encode or decode")

    parser_encode = subparsers.add_parser("encode", help="Hide a file within an image.")
    parser_encode.add_argument(
        "-i", "--image", required=True, metavar="COVER_IMAGE",
        help="Path to the cover image (PNG, BMP, or other formats supported by Pillow). PNG output is recommended."
    )
    parser_encode.add_argument(
        "-f", "--file", required=True, metavar="FILE_TO_HIDE",
        help="Path to the file you want to hide."
    )
    parser_encode.add_argument(
        "-o", "--output", required=True, metavar="OUTPUT_IMAGE",
        help="Path to save the output stego-image (e.g., stego.png). PNG format is strongly recommended for lossless storage."
    )
    parser_encode.add_argument(
        "-p", "--password", required=True, metavar="PASSWORD",
        help="Password for AES encryption. Must be the same for encoding and decoding."
    )
    parser_encode.add_argument(
        "--no-compress", action="store_false", dest="compress", default=True,
        help="Disable compression of the hidden file (compression is enabled by default and generally recommended)."
    )

    parser_decode = subparsers.add_parser("decode", help="Extract a hidden file from an image.")
    parser_decode.add_argument(
        "-i", "--image", required=True, metavar="STEGO_IMAGE",
        help="Path to the stego-image (usually PNG) containing hidden data."
    )
    parser_decode.add_argument(
        "-d", "--destination", required=True, metavar="OUTPUT_DIR",
        help="Directory where the extracted file will be saved."
    )
    parser_decode.add_argument(
        "-p", "--password", required=True, metavar="PASSWORD",
        help="Password used during encoding for AES decryption."
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    logging.debug(f"StegX v{__version__} started with args: {args}")

    success = False
    try:
        if args.mode == "encode":
            if not os.path.isfile(args.image):
                raise FileNotFoundError(f"Cover image not found: {args.image}")
            if not os.path.isfile(args.file):
                raise FileNotFoundError(f"File to hide not found: {args.file}")
            if not args.password:
                raise ValueError("Password cannot be empty for encoding.")
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir)
                    logging.info(f"Created output directory: {output_dir}")
                except OSError as e:
                    raise OSError(f"Cannot create output directory '{output_dir}': {e}")
            if not args.output.lower().endswith(".png"):
                logging.warning("Output filename does not end with .png. PNG format is strongly recommended for lossless LSB storage.")

            success = perform_encode(args.image, args.file, args.output, args.password, args.compress)

        elif args.mode == "decode":
            if not os.path.isfile(args.image):
                raise FileNotFoundError(f"Stego image not found: {args.image}")
            if not os.path.exists(args.destination):

                try:
                    os.makedirs(args.destination)
                    logging.info(f"Created destination directory: {args.destination}")
                except OSError as e:
                    raise OSError(f"Destination directory does not exist and cannot be created: {args.destination} - {e}")
            elif not os.path.isdir(args.destination):
                raise NotADirectoryError(f"Destination path exists but is not a directory: {args.destination}")

            if not args.password:
                raise ValueError("Password cannot be empty for decoding.")

            success = perform_decode(args.image, args.destination, args.password)

    except (FileNotFoundError, ValueError, NotADirectoryError, OSError) as e:
        logging.error(f"Setup Error: {e}")
        print_error(f"{e}")
        sys.exit(1)
    except Exception as e:

        logging.exception("An unexpected setup error occurred:")
        print_error(f"An unexpected error occurred: {e}")
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
