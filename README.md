![Stegx_Github](https://github.com/user-attachments/assets/f569fc67-7c0a-47ca-833e-d088ab1cb243)

# StegX: Non-linear LSB Steganography Tool with AES Encryption

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Parrot OS Verified](https://img.shields.io/badge/Parrot%20OS-Verified-brightgreen?logo=linux)](https://parrotsec.org/)
[![Steganalysis Tested](https://img.shields.io/badge/Steganalysis-Tested-blueviolet)]()
[![Security: AES-GCM](https://img.shields.io/badge/Security-AES--256--GCM-critical)]()
[![Tests: 51 Passed](https://img.shields.io/badge/Tests-51%20passed-brightgreen)]()

StegX is a command-line tool written in Python for hiding files within images using non-linear Least Significant Bit (LSB) steganography technique. It enhances security by encrypting the hidden data using AES-256-GCM and ensures data integrity.

## Features

*   **Hide Files:** Embed any type of file (documents, executables, archives, etc.) within a cover image using Non-linear LSB.
*   **Extract Files:** Retrieve the original hidden file from a stego-image.
*   **Supported Image Formats:** 
    *   **Input (Cover/Stego):** PNG format supported by Pillow. Palette-based images (Mode 'P') are automatically converted to RGBA.
    *   **Output (Stego):** PNG is strongly recommended and used by default for lossless saving, preserving the LSB data.
*   **AES-256-GCM Encryption:** Encrypts the data payload (including metadata) using AES in GCM mode, providing confidentiality and authenticity. Requires a password for both hiding and extraction.
*   **Secure Key Derivation:** Uses PBKDF2HMAC with SHA256 and a unique salt (stored with data) to derive the encryption key from the password, protecting against precomputation attacks.
*   **Data Compression:** Optionally compresses the file data using zlib before encryption to potentially increase the amount of data that can be hidden or reduce the required image size. Compression is only applied if it results in smaller data.
*   **Metadata Storage:** Embeds essential metadata (original filename, original file size, compression status, encryption salt & nonce) securely alongside the file data.
*   **Capacity Check:** Automatically verifies if the cover image has sufficient capacity in its LSBs to store the encrypted and potentially compressed data, including metadata and a termination sentinel.
*   **Data Integrity:** Uses a unique sentinel (`STEGX_EOD`) to mark the end of the hidden data, ensuring correct extraction.
*   **Progress Bar:** Displays a progress bar using `tqdm` for embedding and extraction operations (visible for larger files/images).
*   **Command-Line Interface:** User-friendly CLI powered by `argparse` with clear commands for encoding and decoding.
*   **Robust Error Handling:** Provides informative error messages for common issues like incorrect passwords (InvalidTag), insufficient capacity, file not found, unsupported image modes, or corrupted data.
*   **Cross-Platform:** Designed to run on Windows, macOS, and Linux.

## 🚀 Why StegX is Unique?

- 🔐 AES-256-GCM with integrity checks (InvalidTag-safe)
- 📦 Compression-before-encryption (prevents file-type leaks)
- 🔄 Non-linear, pseudo-random LSB embedding
- ❌ No known forensic/steganography tools could extract hidden data
- 🧪 Manually tested by ParrotSec core developer
- 📜 Fully open-source, MIT licensed

![Alt](https://repobeats.axiom.co/api/embed/f049be619581f2d339bb4a9f0ece66a41408f77c.svg "Repobeats analytics image")

## Installation

1.  **Prerequisites:**
    *   Python 3.8 or higher.
    *   `pip` (Python package installer).

2.  **Clone the Repository (Optional):**
    ```bash
    git clone https://github.com/Delta-Sec/StegX
    cd stegx_project
    ```
    Alternatively, just download the `stegx.py` script and the `stegx_core` directory.

3.  **Install Dependencies:**
    Navigate to the project directory (`stegx_project`) in your terminal and run:
    ```bash
    pip install -r requirements.txt
    ```
    This will install the necessary libraries: `Pillow`, `cryptography`, and `tqdm`.

## Usage

StegX operates in two modes: `encode` (to hide a file) and `decode` (to extract a file).

### Encoding (Hiding a File)

```bash
stegx encode -i <cover_image> -f <file_to_hide> -o <output_image.png> -p <password> [--no-compress] [--verbose]
```

**Arguments:**

*   `-i, --image COVER_IMAGE`: (Required) Path to the input cover image (e.g., `photo.png`, `image.bmp`).
*   `-f, --file FILE_TO_HIDE`: (Required) Path to the file you want to hide (e.g., `secret.txt`, `archive.zip`).
*   `-o, --output OUTPUT_IMAGE`: (Required) Path where the output stego-image will be saved. **Using a `.png` extension is highly recommended** to ensure lossless saving.
*   `-p, --password PASSWORD`: (Required) The password used for AES encryption. Remember this password, as it's needed for decoding.
*   `--no-compress`: (Optional) Disable data compression. By default, StegX tries to compress the data if it reduces the size.
*   `--verbose`: (Optional) Enable detailed debug logging output.

**Example:**

```bash
python stegx.py encode -i landscape.png -f my_document.pdf -o secret_image.png -p "MySecureP@ssw0rd!"
```

### Decoding (Extracting a File)

```bash
stegx decode -i <stego_image.png> -d <output_directory> -p <password> [--verbose]
```

**Arguments:**

*   `-i, --image STEGO_IMAGE`: (Required) Path to the stego-image created by StegX (usually a `.png` file).
*   `-d, --destination OUTPUT_DIR`: (Required) Path to the directory where the extracted file should be saved.
*   `-p, --password PASSWORD`: (Required) The password used during the encoding process.
*   `--verbose`: (Optional) Enable detailed debug logging output.

**Example:**

```bash
python stegx.py decode -i secret_image.png -d ./extracted_files -p "MySecureP@ssw0rd!"
```

This will extract the original file (e.g., `my_document.pdf`) into the `extracted_files` directory (which will be created if it doesn't exist).

## Technical Details

1.  **Payload Creation:**
    *   The file to hide is read.
    *   Metadata (original filename, size, compression flag) is created.
    *   Data is optionally compressed (zlib).
    *   Payload = `[4-byte metadata length] + [JSON metadata] + [file data (compressed or original)]`.
2.  **Encryption:**
    *   A random 16-byte salt is generated.
    *   A 32-byte AES key is derived from the password and salt using PBKDF2-HMAC-SHA256.
    *   A random 12-byte nonce is generated.
    *   The payload is encrypted using AES-256-GCM, which provides authenticated encryption (ciphertext + authentication tag).
    *   Final Encrypted Data = `salt + nonce + ciphertext + tag`.
3.  **LSB Embedding:**
    *   The final encrypted data is converted into a stream of bits.
    *   A unique sentinel (`STEGX_EOD` converted to bits) is appended to the bit stream.
    *   The tool iterates through the image pixels (RGB or Grayscale).
    *   For each pixel, it replaces the least significant bit(s) with bits from the data stream.
        *   RGB/RGBA: Modifies the LSB of R, G, and B channels (3 bits per pixel).
        *   Grayscale (L): Modifies the LSB of the single channel (1 bit per pixel).
    *   The process stops once the entire bit stream (including the sentinel) is embedded.
    *   The modified image is saved (losslessly as PNG).
4.  **LSB Extraction:**
    *   The tool reads the stego-image pixels.
    *   It extracts the LSB from each color channel (or the single channel for grayscale).
    *   It reconstructs the bit stream, constantly checking if the last N bits match the `STEGX_EOD` sentinel.
    *   Once the sentinel is found, the preceding bits form the extracted encrypted data.
5.  **Decryption & File Recovery:**
    *   The salt and nonce are extracted from the beginning of the recovered encrypted data.
    *   The AES key is re-derived using the password and the extracted salt.
    *   AES-GCM decryption is performed. If the password is wrong or data is corrupt, this step fails with an `InvalidTag` error.
    *   The decrypted payload is parsed: metadata length is read, JSON metadata is extracted, and the remaining data is identified.
    *   If the metadata indicates compression, the data is decompressed.
    *   The final data is saved to a file using the original filename from the metadata.

## 🛡️ Security & Steganalysis Resistance

StegX has been tested against multiple steganalysis tools and techniques. It was able to **resist extraction** and **avoid detection** by:

| Tool              | Status       |
|------------------|--------------|
| Stegseek         | ❌ Failed to extract |
| zsteg            | ❌ No patterns found |
| binwalk          | ✅ Clean output |
| exiftool         | ✅ Metadata clean |
| Chi-Square Test  | ✅ Low anomaly (13K vs 119K in Steghide) |
| Entropy Test     | ✅ 7.99 bits/byte (high randomness) |
| Histogram Check  | ✅ High similarity with original |

📎 See detailed comparison in [`Why StegX is Better than steghide.pdf`](./Docs/Why%20Stegx%20Better%20than%20steghide.pdf)


## 🚀 Contributors

Thanks to these amazing people:

[<img src="https://github.com/AyhamAsfoor.png" width="70px;"/><br /><sub><b>AyhamAsfoor</b></sub>](https://github.com/AyhamAsfour)  
Lead Developer

## Troubleshooting / Common Issues

*   **Error: Insufficient image capacity:** The file (after potential compression and encryption overhead) is too large to fit in the LSBs of the chosen cover image. Try a larger image, ensure the cover image is PNG/BMP, or hide a smaller file.
*   **Error: Decryption failed. The password might be incorrect...:** This `InvalidTag` error almost always means the password provided for decoding does not match the one used for encoding, or the stego-image file has been modified or corrupted.
*   **Error: Could not find hidden data marker...:** The `STEGX_EOD` sentinel was not found. This indicates the image was likely not created by StegX or has been significantly altered (e.g., re-saved with lossy compression like JPEG).
*   **Error: Payload or metadata seems corrupted:** The data extracted could be decrypted, but the internal structure (metadata length, JSON format, or decompressed size) is inconsistent. The image might be corrupted.
*   **Unsupported Image Mode:** Ensure the input cover image is in a supported format (RGB, RGBA, L, P). Formats like CMYK are not directly supported for LSB embedding.
*   **Output Image Larger than Expected:** PNG compression might vary. The primary goal of using PNG is lossless storage of LSB data, not minimal file size.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Delta-Sec/StegX/blob/main/LICENSE) file for details.

