import logging
import os

from PIL import Image
from tqdm import tqdm
from typing import Iterator, Union

DATA_SENTINEL = b"\x53\x54\x45\x47\x58\x5f\x45\x4f\x44"    # "STEGX_EOD"
SENTINEL_BITS = "".join(format(byte, '08b') for byte in DATA_SENTINEL)
SENTINEL_LENGTH_BITS = len(SENTINEL_BITS)


def bytes_to_bits_iterator(byte_data: bytes) -> Iterator[int]:
    for byte in byte_data:
        for i in range(8):
            yield (byte >> (7 - i)) & 1


def bits_to_bytes(bits: Union[Iterator[int], str]) -> bytes:
    byte_list = []
    current_byte = 0
    bit_count = 0
    for bit in bits:
        bit_val = int(bit)
        if bit_val not in (0, 1):
            raise ValueError("Input contains non-binary values")

        current_byte = (current_byte << 1) | bit_val
        bit_count += 1
        if bit_count == 8:
            byte_list.append(current_byte)
            current_byte = 0
            bit_count = 0

    if bit_count != 0:
        logging.warning(
            f"Partial byte encountered at the end ({bit_count} bits)"
            f" This might indicate data corruption or an incomplete extraction.")

    return bytes(byte_list)


def calculate_lsb_capacity(image: Image.Image) -> int:
    width, height = image.size
    mode = image.mode

    capacity = 0
    if mode in ('RGB', 'RGBA'):
        capacity = width * height * 3
    elif mode == 'L':
        capacity = width * height
    else:
        raise ValueError(f"Unsupported image mode for LSB: {mode}. Convert to RGB or L first.")

    effective_capacity = capacity - SENTINEL_LENGTH_BITS
    return max(0, effective_capacity)


def embed_data(cover_image_path: str, data_to_hide: bytes, output_image_path: str):
    logging.info(f"Attempting to embed data into {cover_image_path}")
    try:
        image = Image.open(cover_image_path)

        if not output_image_path.lower().endswith(".png"):
            logging.warning("Output file does not end with .png. Saving as PNG to ensure lossless LSB storage.")
            output_image_path = os.path.splitext(output_image_path)[0] + ".png"

        if image.mode == 'P':
            logging.info(f"Converting image mode from {image.mode} to RGBA for LSB embedding.")
            image = image.convert("RGBA")
        elif image.mode not in ('RGB', 'RGBA', 'L'):
            raise ValueError(f"Unsupported image mode: {image.mode}. Please use RGB, RGBA, L, or P.")

        width, height = image.size
        capacity = calculate_lsb_capacity(image)
        logging.info(f"Image: {width}x{height}, Mode: {image.mode}, Capacity (excl. sentinel): {capacity} bits")

        bits_to_embed_iter = bytes_to_bits_iterator(data_to_hide)
        bits_string = "".join(map(str, bits_to_embed_iter))
        total_bits_needed = len(bits_string) + SENTINEL_LENGTH_BITS

        logging.info(f"Data size: {len(data_to_hide)} bytes ({len(bits_string)} bits)")
        logging.info(f"Total bits needed (incl. sentinel): {total_bits_needed}")

        if len(bits_string) > capacity:
            raise ValueError(
                f"Data too large for image capacity. Needs {len(bits_string)} bits, but only {capacity}"
                f" available (excluding sentinel)."
            )

        data_bit_stream = bits_string + SENTINEL_BITS
        data_iter = iter(data_bit_stream)

        stego_image = image.copy()
        pixels = stego_image.load()
        bit_count = 0

        with tqdm(total=total_bits_needed, unit="bit", desc="Embedding data", leave=False) as pbar:
            for y in range(height):
                for x in range(width):
                    try:
                        pixel = list(pixels[x, y])

                        if image.mode in ('RGB', 'RGBA'):
                            for i in range(3):
                                bit = next(data_iter)
                                pixel[i] = (pixel[i] & ~1) | int(bit)
                                pbar.update(1)
                                bit_count += 1
                        elif image.mode == 'L':
                            bit = next(data_iter)
                            pixel_val = (pixels[x, y] & ~1) | int(bit)
                            pixel = tuple([pixel_val])
                            pbar.update(1)
                            bit_count += 1
                        else:
                            raise RuntimeError(f"Unexpected image mode during embedding: {image.mode}")

                        pixels[x, y] = tuple(pixel)

                    except StopIteration:

                        logging.info(f"Finished embedding {bit_count} bits.")
                        stego_image.save(output_image_path, "PNG")
                        logging.info(f"Stego image saved to {output_image_path}")
                        return

        logging.error("Loop finished but StopIteration was not raised. Potential logic error.")
        raise RuntimeError("Embedding process completed unexpectedly.")

    except FileNotFoundError:
        logging.error(f"Cover image not found: {cover_image_path}")
        raise
    except ValueError as e:
        logging.error(f"Embedding failed: {e}")
        raise
    except IOError as e:
        logging.error(f"Image file error: {e}")
        raise
    except Exception as e:
        logging.exception(f"An unexpected error occurred during embedding: {e}")
        raise


def extract_data(stego_image_path: str) -> bytes:
    logging.info(f"Attempting to extract data from {stego_image_path}")
    try:
        image = Image.open(stego_image_path)
        width, height = image.size
        mode = image.mode
        pixels = image.load()
        logging.info(f"Image: {width}x{height}, Mode: {mode}")

        if mode not in ('RGB', 'RGBA', 'L'):

            if mode == 'P':
                logging.info(f"Converting image mode from {mode} to RGBA for LSB extraction.")
                image = image.convert("RGBA")
                pixels = image.load()
                mode = image.mode
            else:
                raise ValueError(f"Unsupported image mode for LSB extraction: {mode}. Expected RGB, RGBA, or L.")

        extracted_bits = []
        sentinel_buffer = ""
        total_pixels = width * height
        processed_pixels = 0

        with tqdm(total=total_pixels, unit="pixel", desc="Extracting data", leave=False) as pbar:
            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]
                    if mode in ('RGB', 'RGBA'):
                        for i in range(3):
                            lsb = pixel[i] & 1
                            extracted_bits.append(str(lsb))
                            sentinel_buffer += str(lsb)

                            if len(sentinel_buffer) > SENTINEL_LENGTH_BITS:
                                sentinel_buffer = sentinel_buffer[1:]

                            if len(sentinel_buffer) == SENTINEL_LENGTH_BITS and sentinel_buffer == SENTINEL_BITS:
                                logging.info(f"Sentinel found after extracting {len(extracted_bits)} bits.")

                                data_bits = "".join(extracted_bits[:-SENTINEL_LENGTH_BITS])
                                return bits_to_bytes(data_bits)
                    elif mode == 'L':
                        lsb = pixel & 1
                        extracted_bits.append(str(lsb))
                        sentinel_buffer += str(lsb)
                        if len(sentinel_buffer) > SENTINEL_LENGTH_BITS:
                            sentinel_buffer = sentinel_buffer[1:]
                        if len(sentinel_buffer) == SENTINEL_LENGTH_BITS and sentinel_buffer == SENTINEL_BITS:
                            logging.info(f"Sentinel found after extracting {len(extracted_bits)} bits.")
                            data_bits = "".join(extracted_bits[:-SENTINEL_LENGTH_BITS])
                            return bits_to_bytes(data_bits)

                    processed_pixels += 1
                    if processed_pixels % 1000 == 0:
                        pbar.update(1000)

            pbar.update(total_pixels - processed_pixels)

        logging.error("Sentinel not found in the image. Data might be corrupted or not present.")
        raise ValueError("End-of-data sentinel not found in the image.")

    except FileNotFoundError:
        logging.error(f"Stego image not found: {stego_image_path}")
        raise
    except ValueError as e:
        logging.error(f"Extraction failed: {e}")
        raise
    except IOError as e:
        logging.error(f"Image file error: {e}")
        raise
    except Exception as e:
        logging.exception(f"An unexpected error occurred during extraction: {e}")
        raise
