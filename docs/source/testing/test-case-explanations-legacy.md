---
orphan: true
---

# StegX Test Case Explanations (legacy)

This document explains the purpose and importance of each test case in the StegX testing suite, organized by test category.

## 1. Unit Tests

### 1.1 Steganography Module Tests (`test_steganography.py`)

#### Basic Functionality Tests
- **test_bytes_to_bits_iterator**: Verifies the correct conversion of bytes to bits, which is fundamental for LSB steganography.
- **test_bits_to_bytes**: Ensures the reverse operation (bits to bytes) works correctly, critical for data extraction.
- **test_calculate_lsb_capacity**: Validates the capacity calculation for different image types, preventing attempts to hide data that exceeds capacity.

#### Core Steganography Tests
- **test_embed_and_extract_data**: Tests the complete embed-extract cycle to ensure data integrity is maintained throughout the process.
- **test_embed_data_capacity_error**: Verifies proper error handling when attempting to embed data that exceeds image capacity.
- **test_extract_data_no_sentinel**: Ensures the tool correctly handles images with no hidden data by checking for sentinel markers.

#### Edge Cases and Error Handling
- **test_file_not_found_errors**: Validates proper error handling for non-existent files.
- **test_palette_image_conversion**: Tests automatic conversion of palette images to RGB/RGBA, ensuring compatibility with various image formats.
- **test_empty_data**: Verifies the tool can handle embedding and extracting empty data.
- **test_output_path_extension**: Tests handling of non-PNG output extensions, ensuring data is always saved in a lossless format.

### 1.2 Crypto Module Tests (`test_crypto.py`)

#### Key Derivation Tests
- **test_derive_key**: Verifies that key derivation produces consistent, secure keys from passwords and salts.

#### Encryption Tests
- **test_encrypt_data**: Ensures encryption produces different outputs for the same input due to random salt and nonce.
- **test_encrypt_data_input_validation**: Validates proper validation of input types and values.

#### Decryption Tests
- **test_decrypt_data**: Verifies that decryption correctly recovers the original data.
- **test_decrypt_data_wrong_password**: Ensures decryption fails with incorrect passwords, a critical security feature.
- **test_decrypt_data_corrupted**: Verifies that corrupted ciphertext is detected and rejected.
- **test_decrypt_data_input_validation**: Validates proper validation of input types and values.

#### Encryption-Decryption Cycle
- **test_encrypt_decrypt_cycle**: Tests the complete encrypt-decrypt cycle with various data types and sizes.

### 1.3 Utils Module Tests (`test_utils.py`)

#### Logging Tests
- **test_setup_logging**: Verifies proper configuration of the logging system.

#### Compression Tests
- **test_compress_decompress_data**: Ensures data compression and decompression maintain data integrity.
- **test_decompress_invalid_data**: Verifies proper error handling for invalid compressed data.

#### Payload Handling Tests
- **test_create_payload**: Tests payload creation with and without compression.
- **test_create_payload_file_not_found**: Validates error handling for non-existent files.
- **test_parse_payload**: Ensures correct parsing of payloads with and without compression.
- **test_parse_payload_with_compression**: Specifically tests compressed payload parsing.
- **test_parse_payload_invalid**: Validates error handling for various invalid payload formats.

#### File Handling Tests
- **test_save_extracted_file**: Verifies correct saving of extracted files.
- **test_save_extracted_file_directory_not_found**: Tests error handling for non-existent directories.
- **test_save_extracted_file_unsafe_filename**: Ensures proper sanitization of potentially unsafe filenames.
- **test_save_extracted_file_io_error**: Validates error handling for I/O errors during file saving.

## 2. Integration Tests

### 2.1 Encode Flow Tests (`test_encode_flow.py`)

#### Complete Flow Tests
- **test_encode_flow_integration**: Tests the complete encode flow from payload creation to embedding, ensuring all components work together correctly.
- **test_high_level_encode_decode_integration**: Tests the high-level encode and decode functions that users directly interact with.

#### Error Handling Tests
- **test_encode_flow_error_handling**: Verifies proper error handling in the integrated encode flow.

#### File Type Tests
- **test_encode_decode_different_file_types**: Tests encoding and decoding of various file types to ensure compatibility.

## 3. System Tests

### 3.1 CLI Tests (`test_cli.py`)

#### Basic CLI Tests
- **test_cli_encode**: Tests the CLI encode command with valid inputs.
- **test_cli_decode**: Tests the CLI decode command with valid inputs.

#### CLI Option Tests
- **test_cli_verbose**: Verifies the verbose flag produces additional debug output.
- **test_cli_no_compress**: Tests the no-compress flag disables compression.

#### CLI Error Handling
- **test_cli_error_handling**: Validates proper error handling for invalid CLI inputs.

#### CLI Help and Version
- **test_cli_help**: Ensures the help command provides useful information.
- **test_cli_version**: Verifies the version command displays version information.

#### End-to-End Tests
- **test_end_to_end_large_file**: Tests the complete workflow with a large file, simulating real-world usage.

## 4. Performance Tests

### 4.1 Performance Tests (`test_performance.py`)

#### File Size Performance
- **test_encode_performance_file_size**: Measures encoding performance with different file sizes to identify potential bottlenecks.

#### Image Size Performance
- **test_encode_performance_image_size**: Measures encoding performance with different image sizes to understand scaling behavior.

#### Decoding Performance
- **test_decode_performance**: Measures decoding performance with different file sizes.

#### Compression Effectiveness
- **test_compression_effectiveness**: Evaluates the effectiveness of compression for different file types, helping users understand when compression is beneficial.

#### Memory Usage
- **test_memory_usage**: Monitors memory consumption during encoding and decoding to identify potential memory leaks or excessive usage.

## 5. Security Tests

### 5.1 Security Tests (`test_security.py`)

#### Password Security
- **test_password_strength**: Evaluates the impact of password strength on key derivation, critical for understanding security implications.

#### Cryptographic Security
- **test_crypto_robustness**: Tests the robustness of the cryptographic implementation against various attacks.

#### Data Integrity
- **test_tamper_resistance**: Verifies resistance to tampering with the stego image, ensuring data integrity.

#### Steganalysis Resistance
- **test_steganalysis_resistance**: Tests resistance to basic steganalysis techniques, important for maintaining stealth.

#### Input Validation
- **test_malformed_input_handling**: Ensures proper handling of malformed inputs to prevent crashes or security vulnerabilities.
- **test_command_injection_resistance**: Tests resistance to command injection attacks via filenames, critical for security in Kali Linux environments.

## Importance of Comprehensive Testing for StegX

### Security Considerations
For a steganography tool like StegX, especially one intended for Kali Linux users, security testing is paramount. The security tests verify that:
- Encryption is properly implemented and resistant to attacks
- Hidden data cannot be easily detected by steganalysis
- The tool is resistant to tampering and malicious inputs
- Password handling is secure and robust

### Reliability Considerations
The unit, integration, and system tests ensure that:
- All core functions work correctly in isolation
- Components integrate properly to form a cohesive system
- The CLI interface correctly handles user inputs and provides useful feedback
- Error handling is robust and informative

### Performance Considerations
The performance tests help users understand:
- How the tool scales with different file and image sizes
- The effectiveness of compression for different file types
- Memory usage patterns that might affect operation on resource-constrained systems

### Kali Linux Specific Considerations
As a tool for Kali Linux, StegX must be particularly robust against:
- Malicious inputs that might attempt to exploit the system
- Command injection and path traversal attacks
- Resource constraints in various deployment scenarios

This comprehensive test suite ensures that StegX meets the high standards expected of security tools in the Kali Linux ecosystem.

---

## Test Suites Added in StegX 2.0

The 2.0 rewrite introduced five new unit suites covering the new modules.
These explanations supplement (not replace) the sections above.

### `tests/unit/test_kdf.py` — KDF hierarchy

* `test_argon2id_master_key_is_deterministic` — same (password, salt, params)
  always yields the same 32-byte master key.
* `test_different_password_yields_different_key` — different passwords never
  collide.
* `test_keyfile_changes_key` — mixing a keyfile into the KDF input changes
  the master key even when the password is identical.
* `test_pbkdf2_master_key` — the PBKDF2 fallback path is still deterministic.
* `test_hkdf_domain_separation` — AES / ChaCha / seed / sentinel sub-keys
  derived from the same master are all distinct.
* `test_seed_int_is_non_negative` — the shuffle seed is always a valid
  `random.Random` input.
* `test_legacy_seed_matches_known_derivation` — the v1-compat seed path
  remains deterministic.
* `test_empty_password_rejected` — the KDF refuses empty passwords.

### `tests/unit/test_header.py` — v2 container header

* `test_pack_unpack_roundtrip_argon2id` / `test_pack_unpack_roundtrip_pbkdf2`
  — header serialisation is lossless for both KDF choices.
* `test_unpack_rejects_bad_magic` / `test_unpack_rejects_bad_version` —
  corrupted header bytes are rejected explicitly.
* `test_pack_rejects_bad_salt_size` — invariants on field lengths are
  enforced on pack.
* `test_as_aad_zeros_inner_length` — AAD canonicalisation forces
  `inner_ct_length` to zero so encrypt-time and decrypt-time AADs match.

### `tests/unit/test_shamir.py` — Shamir k-of-n secret sharing

* `test_split_combine_basic` — any ≥ k shares reconstruct the secret.
* `test_fewer_than_threshold_does_not_recover` — < k shares produce
  effectively random output.
* `test_identical_x_coords_rejected` — duplicate shares raise.
* `test_invalid_parameters` — enforces 1 ≤ k ≤ n ≤ 255 and non-empty secret.
* `test_roundtrip_random_sizes` — parametrised round-trip over a range of
  secret sizes.

### `tests/unit/test_compression.py` — multi-algorithm compressor

* `test_roundtrip_text` / `test_roundtrip_binary` — every winner-algorithm
  output can be decompressed back to the input.
* `test_none_wins_for_incompressible` — high-entropy inputs fall through to
  `none` rather than paying compressor overhead.
* `test_best_beats_or_ties_fast` — `best` mode never loses to `fast`.
* `test_fast_mode_limits_to_zlib` — `fast` restricts the field as documented.
* `test_unknown_mode_raises` / `test_unknown_alg_decompress_raises` — API
  contract boundary checks.
* `test_available_algorithms_has_stdlib` — zlib/lzma/bz2 are always present.
* `test_decompress_each_stdlib_alg` — explicit decompressor smoke test for
  each codec.

### `tests/unit/test_io_sources.py` — URL cover fetcher

* `test_is_url_accepts_http_and_https` / `test_is_url_rejects_other_schemes`
  — only `http`/`https` are accepted; no `file://`, no `ftp://`, no
  relative paths.
* `test_fetch_valid_png` — a `Content-Type: image/png` response is
  downloaded, verified by Pillow, and usable.
* `test_fetch_rejects_non_image_content_type` — `application/octet-stream`
  is refused.
* `test_fetch_rejects_malformed_image` — non-image bytes that arrive under
  `image/png` fail Pillow's `verify()` and are deleted.
* `test_fetch_404` — HTTP errors propagate as `ValueError`.
* `test_download_cap_constant_is_reasonable` — the 50 MiB cap is a sanity
  ceiling preventing DoS via attacker-controlled URLs.

### Updated — `tests/unit/test_crypto.py`

Rewritten for the v2 AEAD container:

* `test_encrypt_emits_valid_header` — the first 56 bytes parse as a valid v2
  header with correct `inner_ct_length`.
* `test_roundtrip_argon2id` / `test_roundtrip_pbkdf2` — both KDFs round-trip.
* `test_wrong_password_fails` / `test_corrupted_ciphertext_fails` — the AEAD
  tag rejects both.
* `test_corrupted_header_aad_fails` — flipping any flag bit in the header
  invalidates the tag (because the header is AAD).
* `test_dual_cipher_roundtrip` — AES-GCM + ChaCha20-Poly1305 layering.
* `test_keyfile_roundtrip` / `test_keyfile_required_for_decrypt` /
  `test_keyfile_wrong_bytes_fails` — keyfile second-factor semantics.
* `test_legacy_v1_roundtrip` — the v1 fallback decrypt path still works for
  `salt || nonce || ct` blobs.

### Updated — `tests/unit/test_steganography.py`

All tests now pass a password. New coverage:

* `test_embed_and_extract_rgb` / `test_embed_and_extract_grayscale` — core
  v2 round-trip.
* `test_wrong_password_rejected` — extraction with the wrong password
  raises.
* `test_max_fill_ratio_enforced` — the capacity ceiling flag refuses
  oversize payloads.
* `test_dual_cipher_and_matrix_embedding` — the heaviest combined path
  still round-trips.
* `test_keyfile_enforced` — a keyfile-protected stego cannot be decoded
  without the keyfile.
* `test_decoy_deniability` — embedding with a decoy gives *two* valid
  recovery paths (real password → real payload; decoy password → decoy
  payload), with the decoy frame parsed through `parse_payload` to yield
  the original file contents.

### `tests/security/test_security.py` — AAD + sentinel + change-rate bounds

* `test_aad_tamper_is_detected` — flipping a flag byte in the header
  invalidates the GCM tag.
* `test_sentinel_is_image_bound` — different cover dimensions yield
  different sentinels under the same sentinel key.
* `test_stego_changes_are_low_rate` — LSB matching never changes a channel
  by more than 1, and the per-pixel change rate is bounded.
* `test_output_has_no_pillow_software_chunk` — the saved PNG does not leak
  `Software = Pillow X.Y`.
* `test_header_layout_stable` — header size is a hard 56 bytes.

### `tests/integration/test_encode_flow.py`

* `test_full_encode_decode_flow` — CLI entry points `perform_encode` and
  `perform_decode` round-trip through an `argparse.Namespace` mock.
* `test_decode_to_stdout` / `test_decode_dash_destination_means_stdout` —
  `--stdout` and `-d -` both pipe the decrypted payload to stdout without
  touching disk.
* `test_decode_requires_destination_or_stdout` — at least one output mode
  is required.

### `tests/system/test_cli.py`

End-to-end subprocess tests that pipe the password via `--password-stdin`,
covering `--help`, `--version`, the full encode→decode cycle through the
`stegx.py` script, and a wrong-password exit-code check.
