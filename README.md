![Stegx_Github](https://github.com/user-attachments/assets/f569fc67-7c0a-47ca-833e-d088ab1cb243)

# StegX 2.0: Authenticated Non-Linear LSB Steganography with Argon2id + AES-GCM

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Parrot OS Verified](https://img.shields.io/badge/Parrot%20OS-Verified-brightgreen?logo=linux)](https://parrotsec.org/)
[![Steganalysis Tested](https://img.shields.io/badge/Steganalysis-Tested-blueviolet)]()
[![Security: AES-GCM + ChaCha20](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20ChaCha20--Poly1305-critical)]()
[![KDF: Argon2id](https://img.shields.io/badge/KDF-Argon2id-brightgreen)]()
[![Tests: 255 Passed](https://img.shields.io/badge/Tests-255%20passed-brightgreen)]()
[![Referenced in Grokipedia](https://img.shields.io/badge/Referenced%20in-Grokipedia-orange)](https://grokipedia.com/page/Steganography_in_Python)

StegX hides files inside PNG images using password-shuffled LSB embedding and
authenticated encryption. Version 2 is a ground-up security rewrite built
around a versioned container format, Argon2id key derivation, domain-separated
HKDF sub-keys, LSB-matching (±1) embedding that defeats chi-square steganalysis
and — optionally — ChaCha20-Poly1305 dual-cipher, F5-style matrix embedding,
adaptive cost-map filtering, keyfile 2FA, plausible-deniability decoy payloads,
and k-of-n Shamir secret sharing across multiple cover images.

> **Technical Evaluation Report 📊**  
> For a complete, in-depth evaluation of StegX v2.0's cryptographic strength, statistical invisibility (Chi-Square/Entropy metrics), and a head-to-head performance comparison against legacy tools like **Steghide**, please read our comprehensive **[StegX v2.0 Technical Evaluation & Benchmark Report](./StegX_v2_Technical_Report.md)**.

## What's New in 2.0

### Cryptography
* **Argon2id** replaces PBKDF2 as the default password KDF (PBKDF2 still
  selectable via `--kdf pbkdf2` at 600k iterations, and the legacy v1 format
  is still readable for backwards compatibility).
* **HKDF sub-keys** derive independent AES-GCM, ChaCha20-Poly1305,
  position-shuffle seed and sentinel keys from one master key — so the slow
  password KDF runs once per operation.
* **AEAD with associated-data** binds the entire container header
  (version/flags/KDF params/salts/nonces) to the ciphertext, so any tampering
  invalidates the GCM tag.
* **Dual-cipher mode** (`--dual-cipher`) layers ChaCha20-Poly1305 on top of
  AES-256-GCM with independent keys — defence in depth against a catastrophic
  break of either cipher.
* **Keyfile 2FA** (`--keyfile PATH`) mixes an external binary into the KDF
  input; password alone no longer suffices.

### Compression
* **Multi-algorithm compressor** (`--compression best`, default): every
  payload is fed to zlib-9, LZMA2-extreme, bzip2-9, zstd-22, **zstd-22 with
  a bundled pre-trained dictionary**, and brotli-11 in parallel; the smallest
  output wins and is tagged in the metadata so the decoder knows what to
  reverse. Typical savings on compressible data (text/JSON/code) are
  **40-75% smaller than zlib alone**. The dictionary (~5 KiB, shipped at
  `src/stegx/data/stegx_dict_v1.zstd`) was trained on a corpus of common
  file-type headers (PE/ELF/PDF/ZIP/JSON/text/image) so it wins particularly
  on small payloads under ~1 KiB where plain zstd pays its header overhead.
  Random/encrypted payloads fall through to `none` (storing raw bytes).
* **`--compression fast`** for latency-critical scenarios — zlib only, same
  behaviour as pre-2.0.

### Multi-file batch embed
* `stegx encode -f a.zip b.txt c.pdf -o out.png` bundles multiple inputs
  into an in-memory tar archive before compression and encryption. On
  decode, the bundle flag in metadata triggers transparent extraction —
  each member is written to the destination directory with its original
  filename. Path traversal attempts (`../`, absolute paths, symlinks,
  devices) are rejected during extraction.

### Cover selection (`stegx pick-cover`)
* `stegx pick-cover --dir ./covers --payload secret.zip` ranks every
  image in a directory by capacity and Shannon entropy, and picks the
  best fit for a given payload. Useful for choosing a cover that has
  enough headroom AND enough texture to hide LSB modifications.

### Steganography
* **LSB matching (±1)** replaces LSB replacement by default — defeats the
  asymmetry exploited by chi-square and RS analysis.
* **Adaptive embedding** (`--adaptive`) filters pixel positions by
  cost map. Two modes are available via `--adaptive-mode`:
  - `laplacian` (default, fast) — keeps positions with the highest edge
    response. Adequate for classical steganalysers.
  - `hill` — HILL-inspired cost map (Li et al., ICIP 2014) with a KB
    high-pass + double box-blur pipeline. Stronger against CNN-based
    steganalysers (SRNet / YeNet) at a small extra compute cost.
* **Matrix (F5) embedding** (`--matrix-embedding`) uses Hamming(7,3) coding
  to cut the per-bit change rate by ~2.3×.
* **Per-image HMAC sentinel** replaces the fixed `STEGX_EOD` marker, so the
  sentinel varies with password and cover and can't be pattern-matched.
* **Capacity ceiling** (`--max-fill PCT`, default 25%) rejects oversize
  payloads that would be trivially detectable by CNN steganalysers.
* **PNG metadata stripping** clears Pillow's `Software` fingerprint chunk;
  the output's encoder parameters mirror the cover's (`compress_level`) so
  file-size and chunk comparisons don't flag the stego.

### Operational hardening
* **`getpass` by default** for password entry, plus `--password-stdin` for
  scripting. `-p` still works but warns loudly — it leaks into shell history
  and `ps`.
* **`zxcvbn` password-strength gate**: warn on score < 3; `--strict-password`
  refuses weak passwords outright.
* **Unified decode error message** — wrong password, wrong keyfile, and
  non-StegX image all report the same text, removing an oracle.
* **Constant-time sentinel compare** via `hmac.compare_digest`.
* **OS-level memory locking** via ``mlock(2)`` on Linux / macOS and
  ``VirtualLock`` on Windows for every master key and HKDF sub-key —
  prevents secrets from being paged to swap / hibernation files. Falls
  back to plain zeroisation if the OS rejects the lock (e.g. without
  ``CAP_IPC_LOCK`` or sufficient working-set quota).
* **Best-effort memory wipe** of master keys and derived sub-keys after use.
* **`--fips` mode** restricts the pipeline to FIPS 140-validated
  primitives: PBKDF2-HMAC-SHA256, AES-256-GCM, HKDF-SHA256 and zlib-only
  compression. Refuses Argon2id, ChaCha20-Poly1305, brotli, lzma, bz2 and
  zstd. Suitable for compliance-bound environments.
* **Versioned container** (magic byte + version byte + flags) makes future
  algorithm upgrades non-breaking.

### Advanced features
* **Plausible-deniability decoy** (`--decoy-file` / `--decoy-password`) —
  the cover is split into two disjoint regions; either password unlocks only
  its own region. Without both passwords, an observer cannot tell whether a
  second region carries data.
* **Paranoid cover split** (`--always-split-cover`) — always reserves the
  decoy half and fills it with cryptographically random bits whenever no
  real decoy is supplied. Equalises LSB modification density across both
  halves so a statistical observer cannot distinguish "decoy in use" from
  "no decoy" cases. Costs 50 % of cover capacity; opt-in only.
* **k-of-n Shamir split** (`stegx shamir-split` / `stegx shamir-combine`) —
  distribute a secret across n cover images; any k reconstruct it.

## ⚠️ Breaking change from 1.x

The v2 payload format is **not backwards-compatible** with stego images
produced by StegX ≤ 1.2.1 (sentinel, seed derivation and container layout all
changed). StegX 2.0 *can still read* v1 stego images transparently via a
fallback path, but new stego images use v2. Re-encode anything important.

## Installation

StegX 2.0 can be installed across multiple platforms using your preferred package manager.

### 📦 PyPI (Python Package)
The recommended way for most users. Requires Python 3.8+.
```bash
pip install stegx-cli
```
*Optional:* To install with compression algorithms and password strength evaluation:
```bash
pip install stegx-cli[compression,strength]
```

### 🐧 Arch Linux (AUR)
If you are on Arch Linux or Manjaro, you can install the native package from the Arch User Repository:
```bash
yay -S stegx
```

### 🐳 Docker
A pre-built, multi-architecture Docker image is available on Docker Hub and GitHub Container Registry.
```bash
docker pull ayhamasfoor/stegx:latest
```
**Usage Example:**
```bash
docker run --rm -i -v "$PWD:/work" ayhamasfoor/stegx \
    encode -i /work/cover.png -f /work/secret.zip \
           -o /work/out.png --password-stdin <<< "YourStrongPassword"
```

### 🛍️ Snap (Ubuntu & Linux)
Install securely via the Snap Store on any supported Linux distribution:
```bash
sudo snap install stegx
```

### 🛠️ Build from Source
If you prefer to run it directly from the source code:
```bash
git clone https://github.com/Delta-Sec/StegX
cd StegX
pip install -e .
```

*Note: Shell completions are available in the `completions/` directory.*

## Continuous Integration

GitHub Actions workflows are checked in under `.github/workflows/`:

* [ci.yml](.github/workflows/ci.yml) runs on every push + PR:
  - `pytest` matrix on Python 3.9 / 3.10 / 3.11 / 3.12 / 3.13 (Linux) +
    a 3.12 Windows row.
  - `docker build` + smoke test of `stegx --version` and
    `stegx benchmark` inside the built image.
  - `python -m build` + `twine check` producing an artefact for every
    successful run.
* [release.yml](.github/workflows/release.yml) fires on `v*.*.*` tags
  (or manual dispatch):
  - Builds + publishes the wheel and sdist to PyPI (expects a
    `PYPI_API_TOKEN` repo secret — or switch to OIDC trusted
    publishing; the workflow has commented guidance).
  - Builds + pushes a multi-arch (`amd64` + `arm64`) Docker image to
    `ghcr.io/<owner>/stegx` using the standard `GITHUB_TOKEN`.

## Usage

StegX provides four subcommands: `encode`, `decode`, `shamir-split`, `shamir-combine`.

### Encoding (hiding a file)

```bash
stegx encode -i <cover> -f <file> -o <output.png> [options]
```

The password is read from a TTY prompt by default (`getpass`). To script, pipe
it via `--password-stdin`. The legacy `-p` flag is still accepted but will warn.

**Common options:**

| Flag | Description |
|------|-------------|
| `-p, --password PW`        | Password (discouraged — leaks into shell history). |
| `--password-stdin`         | Read password from a single line of stdin. |
| `--keyfile PATH`           | Mix an external binary into the KDF as a second factor. |
| `--yubikey`                | Require a YubiKey HMAC-SHA1 response (slot 2) as an additional hardware factor. Needs `pip install ykman`. |
| `--panic-password PW`      | Arm self-destruct: entering this password at decode time wipes the real region's LSBs before reporting. Mutually exclusive with `--decoy-file`. |
| `--panic-decoy PATH`       | Sacrificial payload returned after panic destruction (omit = silent mode). |
| `--polyglot-zip PATH...`   | After the stego PNG is written, append a ZIP archive of the listed files so the output is simultaneously a valid PNG and a valid ZIP. Public side-channel only; does not affect the hidden StegX payload. |
| `--kdf {argon2id,pbkdf2}`  | Password-based KDF (default: argon2id). |
| `--dual-cipher`            | Layer ChaCha20-Poly1305 over AES-256-GCM. |
| `--adaptive`               | Embed only in high-edge-cost regions (defeats CNN steganalysers). |
| `--matrix-embedding`       | F5-style Hamming(7,3) matrix embedding for the ciphertext body. |
| `--max-fill PCT`           | Refuse payloads filling more than PCT % of capacity (default 25%). |
| `--strict-password`        | Reject passwords with zxcvbn score < 3 (default: warn). |
| `--no-preserve-cover`      | Don't mirror the cover's PNG encoder parameters on save. |
| `--no-compress`            | Disable compression of the payload. |
| `--compression {fast,best}`| `fast` = zlib-9 only; `best` (default) tries zlib, LZMA, bzip2, zstd-22 (+ bundled-dictionary variant) and brotli-11, stores the smallest. |
| `--always-split-cover`     | Paranoia mode: always reserve the decoy half and fill it with random bits even when no `--decoy-file` is set. Halves cover capacity; opt-in. |
| `--fips`                   | Restrict to FIPS 140-validated primitives (PBKDF2 + AES-GCM + zlib). Rejects Argon2id / ChaCha / brotli / lzma / bz2 / zstd. |
| `--decoy-file PATH`        | Hide a decoy payload alongside the real one (plausible deniability). |
| `--decoy-password PW`      | Password for the decoy (prompted if omitted). |

**Cover image from a URL:** the `-i`/`--image` argument accepts an
`http(s)://…` URL. StegX downloads the bytes to a temp file (only
`Content-Type: image/*` is accepted, 50 MiB cap, 30-second timeout), verifies
the image with Pillow, uses it as the cover, and deletes the temp file on
exit. Only image decoding — no scripting, no execution of any kind.

**Examples:**

```bash
# Interactive: prompts for password via getpass
stegx encode -i landscape.png -f secret.pdf -o out.png

# Cover pulled straight from a URL (Imgur, S3, etc.)
stegx encode -i https://i.imgur.com/abc123.png -f secret.zip -o out.png

# Hardened: dual cipher + adaptive + matrix embedding + keyfile
stegx encode -i cover.png -f secret.bin -o out.png \
    --dual-cipher --adaptive --matrix-embedding --keyfile token.bin

# Plausible-deniability decoy
stegx encode -i cover.png -f real.zip -o out.png \
    --decoy-file harmless.txt
```

### Decoding (extracting a file)

```bash
stegx decode -i <stego.png> (-d <output_dir> | --stdout | -d -) [--keyfile PATH]
```

The password is prompted interactively unless `-p`, `--password-stdin`, or
`--keyfile` changes the auth inputs. All failure modes (wrong password, wrong
keyfile, non-StegX image, corrupted data) report the **same** error message on
purpose — to avoid leaking information to an attacker.

**Output destinations:**

* `-d <dir>`       — write the extracted file into `<dir>` (default behaviour).
* `--stdout`       — write decrypted bytes to stdout (no filename preserved).
  Use this to pipe directly into another program without touching disk.
* `-d -`           — same as `--stdout`.

**Examples:**

```bash
# Normal disk output
stegx decode -i out.png -d ./extracted

# Pipe decrypted bytes into another tool (e.g. SSH key into ssh-agent)
stegx decode -i out.png --stdout --password-stdin <<< "$PW" | ssh-add -

# Pipe into jq, openssl, etc.
stegx decode -i out.png --stdout | jq .
```

### Benchmark your machine

```bash
stegx benchmark [--iterations N] [--size-kib K]
stegx benchmark --calibrate [--target-ms 500]
```

Times Argon2id KDF runs and runs the compression multiplexer over a
mixed-ASCII sample. `--calibrate` sweeps Argon2id memory sizes to find
the one that lands closest to `--target-ms` on your CPU — useful before
bumping the project-wide defaults in `src/stegx/kdf.py`.

### Rotate a stego image's credentials

```bash
stegx rewrap -i stego.png [-o new.png]
```

Rotates the password / keyfile / YubiKey on an existing stego image
**without ever materialising the plaintext on disk**. The old
credentials decrypt the inner payload in memory, the old LSB positions
are overwritten with cryptographic noise so they cannot be resurrected,
and the payload is re-embedded with the new credentials. Useful when a
password is suspected compromised or during scheduled key rotation.

### Hash-chained audit log

Every `encode` / `decode` / `rewrap` subcommand accepts `--audit-log PATH`.
Each operation appends one JSONL record containing:

* UTC timestamp
* Operation name + ok/fail bit
* SHA-256 of the cover and/or stego file
* Names (never values) of the security-relevant flags used
* A `prev` link to the previous record's `chain` hash + its own `chain`
  hash over the canonical form of the record

Tampering with any middle record breaks every subsequent `chain` hash;
`stegx.audit_log.verify_chain(path)` walks the file and reports
the first bad line. Payload content is never logged.

### Shamir k-of-n split / combine

Split a secret into `n` shares hidden across `n` cover images — any `k`
reconstruct it.

```bash
# Split: 3-of-5 across 5 covers
stegx shamir-split -k 3 -n 5 -f secret.bin \
    -c c1.png c2.png c3.png c4.png c5.png -O shares/

# Combine: any 3 shares recover the secret
stegx shamir-combine -i shares/stego_share_01.png \
    shares/stego_share_02.png shares/stego_share_03.png \
    -d ./out -o recovered.bin
```

## Technical Details (v2)

### Embedded byte-stream layout (inside pixel LSBs)

```
[16 B  sentinel ]   HMAC(sentinel_key, cover_fingerprint)[:16]
[56 B  header   ]   magic | version | kdf_id | flags | kdf_params
                    | salt(16) | aes_nonce(12) | chacha_nonce(12)
                    | inner_ct_length(4)
[N  B  ciphertext]  AEAD(AES-256-GCM, optionally chained with ChaCha20-Poly1305)
```

### Key hierarchy

```
position_key  = Argon2id(password ‖ keyfile?, FIXED_APP_SALT, default_params)
                    ├─ HKDF("stegx/v2/pixel-shuffle-seed" ‖ fingerprint) → shuffle seed
                    └─ HKDF("stegx/v2/sentinel"          ‖ fingerprint) → sentinel key

master_key    = Argon2id(password ‖ keyfile?, random_salt_from_header, params_from_header)
                    ├─ HKDF("stegx/v2/aes-256-gcm")        → AES key (32 B)
                    └─ HKDF("stegx/v2/chacha20-poly1305")  → ChaCha key (optional)
```

Argon2id defaults: `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`.

### Encryption

1. Build inner payload: `[4-B metadata_len][JSON metadata][file data (optionally zlib-compressed)]`.
2. Derive `master_key` (Argon2id); derive `aes_key` and optional `chacha_key` via HKDF.
3. `aes_ct = AES-GCM(aes_key, aes_nonce, inner, aad=header_with_length_zeroed)`.
4. If `--dual-cipher`: `final_ct = ChaCha20-Poly1305(chacha_key, chacha_nonce, aes_ct, aad=header)`.
5. Final container: `header.pack() ‖ final_ct` (length field populated after step 3).

### Embedding

1. `position_key` → `seed_int` → shuffle every pixel-channel index.
2. If `--adaptive`: drop positions outside the top Laplacian-edge percentile.
3. If `--decoy-file`: partition all positions into two disjoint regions by a
   cover-fingerprint-only deterministic shuffle; real payload uses one region,
   decoy uses the other.
4. LSB-matching (±1) on sentinel + header + ciphertext; matrix (F5 Hamming 7-3)
   optionally on the ciphertext body only.
5. Save as PNG with stripped metadata chunks and cover-matched `compress_level`.

### Extraction

1. Derive `position_key` → shuffled positions → read first 16 bytes; compare
   against HMAC-derived sentinel (constant-time).
2. On match, read 56-byte header, parse KDF params, derive `master_key`.
3. Read `inner_ct_length` bytes of ciphertext, reverse dual-cipher if flagged,
   decrypt with AES-GCM. AEAD tag verifies that the header was not tampered.
4. Parse metadata, decompress if flagged, write to output directory with a
   sanitised filename.

Sentinel-then-AEAD-tag means **wrong password / wrong keyfile / non-StegX
image** all fail with the same generic error — no oracle.

## 🛡️ Security & Steganalysis Resistance

StegX has been tested against multiple steganalysis tools and techniques. It was able to **resist extraction** and **avoid detection** by:

| Tool              | Status       |
|------------------|--------------|
| Stegseek         | ❌ Failed to extract |
| zsteg            | ❌ No patterns found |
| binwalk          | ✅ Clean output |

## Troubleshooting / Common Issues

*   **Error: Insufficient image capacity:** The file (after potential compression and encryption overhead) is too large to fit in the LSBs of the chosen cover image. Try a larger image, ensure the cover image is PNG/BMP, or hide a smaller file.
*   **Error: Decryption failed. The password might be incorrect...:** This `InvalidTag` error almost always means the password provided for decoding does not match the one used for encoding, or the stego-image file has been modified or corrupted.
*   **Error: Could not find hidden data marker...:** The `STEGX_EOD` sentinel was not found. This indicates the image was likely not created by StegX or has been significantly altered (e.g., re-saved with lossy compression like JPEG).
*   **Error: Payload or metadata seems corrupted:** The data extracted could be decrypted, but the internal structure (metadata length, JSON format, or decompressed size) is inconsistent. The image might be corrupted.
*   **Unsupported Image Mode:** Ensure the input cover image is in a supported format (RGB, RGBA, L, P). Formats like CMYK are not directly supported for LSB embedding.
*   **Output Image Larger than Expected:** PNG compression might vary. The primary goal of using PNG is lossless storage of LSB data, not minimal file size.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Delta-Sec/StegX/blob/main/LICENSE) file for details.
