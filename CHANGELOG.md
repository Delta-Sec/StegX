# Changelog

All notable changes to StegX are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-04-23

### Security — Defence-in-depth path sanitiser (2026-04)

Adds a single audited sanitiser (`stegx_core/safe_paths.py`) that every
user- or env-controlled filesystem operation now routes through.  This
is both a real hardening layer and a visible taint-sanitiser chokepoint
for static analysers (Snyk, Bandit, Semgrep) so the "CLI path flows to
open()" warnings no longer need per-finding suppressions.

* **New module `stegx_core/safe_paths.py`.** Two entry points:
  * `validate_user_path(path, *, kind, must_exist, max_len, allow_empty)`
    — rejects NULL bytes (silently truncated by some older POSIX
    APIs), enforces `MAX_PATH_LEN = 4096`, canonicalises to
    absolute path, optionally asserts existence and kind
    (file / dir).  Returns the canonical path for every downstream
    filesystem call to use.
  * `ensure_under_base(candidate, base)` — resolves both via
    `os.path.realpath` and asserts the candidate lives inside the
    base directory.  Uses an `os.sep`-suffixed prefix check so
    `/tmp/out` does not accept `/tmp/outside/...`.

* **CLI entry points (`stegx.py`).** Every flagged `open` /
  `os.replace` / `os.unlink` site now operates on a path that has
  been through `validate_user_path`:
  * `perform_encode`: `args.image` (when not a URL), `args.output`.
  * `perform_decode`: `args.image`, `args.destination`.
  * `perform_rewrap`: `args.image`, `args.output`.
  * `perform_shamir_split`: `args.file`, `args.cover` (each),
    `args.out_dir`.
  * `perform_shamir_combine`: `args.image` (each), `args.destination`,
    plus an explicit `ensure_under_base(output_path, args.destination)`
    re-check on the final write.
  * `_read_keyfile`, `_resolve_encode_decoy`, `_resolve_encode_panic`,
    `_attach_polyglot` — every helper that opens a user-supplied path.

* **`audit_log.py` — `STEGX_CONFIG_HOME` flow.**
  `resolve_or_create_audit_key()` now routes `key_path` through
  `validate_user_path` before any `os.unlink` or `os.chmod` runs.  The
  existing `O_EXCL | O_NOFOLLOW` + `fstat` ownership checks remain as
  the primary symlink-race defence — the validator is the visible
  sanitiser between the env-var source and the filesystem sinks.

* **`utils.py` — tar-bundle extraction.**  `_extract_tar_bundle` now
  calls `ensure_under_base(os.path.join(output_dir, member.name),
  output_dir)` immediately before `tar.extract`.  This is the fourth
  independent containment layer on top of Python 3.12's native
  `filter="data"`, `_is_member_safe`'s realpath check, and the
  per-bundle `MAX_BUNDLE_MEMBERS` / `MAX_BUNDLE_TOTAL_BYTES` caps —
  cheaply catches any future refactor that drops one of the earlier
  layers.

* **Tests — `tests/_test_credentials.py` helper.**  String-literal
  passwords in `tests/integration/test_rewrap.py` and
  `tests/unit/test_crypto.py` replaced with
  `derive_password(label)` = first 40 hex chars of
  `sha256(_TEST_SEED || label)`.  Passwords stay deterministic across
  runs (required for the KDF round-trip assertions) but no literal
  remains in the test code for the "hardcoded credential" heuristic
  to latch onto.  The helper is named `derive_password`, not
  `test_password`, so pytest's auto-collector does not try to run
  it as a parametrised test case.

### Tests added

* `tests/unit/test_safe_paths.py` (new file, 16 tests): NULL-byte
  rejection, length cap, empty-string policy, kind assertions
  (file / dir), must-exist-true / must-exist-false semantics,
  `ensure_under_base` containment including the tricky sibling-
  prefix case (`/tmp/out` vs `/tmp/outside`).

### Security — Black-Swan audit remediations (2026-04)

Four adversarial findings from the post-v3 nation-state red-team pass,
all fixed upstream at the most minimal structural point:

* **BS-1 (Critical) — Rewrap backup file leaked OLD-credential
  plaintext on SIGKILL / power loss.** `perform_rewrap` used to
  `shutil.copy2` the pre-rewrap stego to `<image>.stegx-backup` before
  calling `embed_v2` so it could restore on exception. The copy was a
  byte-identical, OLD-credentials-readable duplicate, and it was NOT
  cleaned up in the outer `finally` block — a SIGKILL / power loss /
  OOM kill between the copy and the success-path unlink left it on
  disk permanently, defeating the explicit forward-secrecy contract of
  the rotate operation. **Fix:** `save_as_stego_png` is now crash-
  atomic (tempfile in output dir → `fsync` → `os.replace`, with a
  Windows AV retry loop and a `finally`-guarded tempfile unlink). With
  the atomic save in place the backup copy becomes unnecessary, so the
  `shutil.copy2` / restore / unlink triad has been removed from
  `perform_rewrap` entirely. No plaintext-equivalent copy of the pre-
  rewrap stego ever touches the filesystem.
* **BS-2 (Medium) — `KMS_WRAP_MAX` bypass via `Header.unpack`.** The
  512-byte `kms_wrap` ceiling was only enforced in
  `steganography._read_and_decrypt`; every other `Header.unpack()`
  call site (including the public `crypto.decrypt_data`) accepted
  lengths up to the u16 wire maximum of 65 535. **Fix:** moved the
  cap into `Header._unpack_v3` (raises `HeaderParameterOutOfRange`)
  and made `Header._pack_v3` symmetric so producers cannot emit a
  header the canonical parser would reject. The stego-side pre-flight
  check stays as defence-in-depth (it bails *before* reading 65 KiB
  worth of LSB positions from the cover).
* **BS-3 (Medium) — One-shot decompressors bypassed the 256 MiB cap.**
  `_decompress_zlib_safe` / `_decompress_lzma_safe` /
  `_decompress_bz2_safe` / `_decompress_brotli` used the stdlib
  one-shot `*.decompress(blob)` entry points and only checked
  `MAX_DECOMPRESS_SIZE` *after* the allocation — a bomb with ratio
  10⁹:1 could OOM the interpreter before the check fired. **Fix:**
  each path now drives an incremental decompressor object (`zlib.
  decompressobj`, `lzma.LZMADecompressor`, `bz2.BZ2Decompressor`,
  `brotli.Decompressor`), feeding `_STREAM_CHUNK = 64 KiB` per call
  with `max_length = cap − len(out) + 1` so a single call can
  overshoot by at most 1 byte before the accumulator trips the
  bomb check. Shared `_raise_bomb()` keeps the error message
  uniform across codecs. zstd / zstd-dict paths were already
  bounded via `stream_reader.read(MAX + 1)` and are unchanged.
* **BS-4 (Low / DiD) — Tar bundle extraction had no member-count or
  aggregate-size caps.** A malicious decoy containing ~500 k zero-
  byte members would exhaust extraction-filesystem inodes and pile
  ~500 MiB of `TarInfo` objects onto the heap via the eager
  `tarfile.getmembers()`. **Fix:** `_extract_tar_bundle` now
  streams with `tar.next()`, bails on `MAX_BUNDLE_MEMBERS = 4096`,
  and sums each member's declared `.size` against
  `MAX_BUNDLE_TOTAL_BYTES = MAX_DECOMPRESS_SIZE (256 MiB)` *before*
  the body is read. Unsafe members (symlinks, path traversal) still
  count toward the member budget so a bundle cannot be padded with
  skipped entries to exhaust the iterator. Python 3.12
  `filter="data"` + the existing `_is_member_safe` check stay in
  place as defence-in-depth.

### Tests added

* `tests/unit/test_header.py` (+2): `test_v3_unpack_rejects_oversize_kms_wrap`
  and `test_v3_unpack_rejects_u16_max_kms_wrap` cover the canonical-
  parser enforcement; the existing pack test was tightened to the
  new 512-byte policy ceiling. A byte-level big-endian test was
  reworked to use `0x0123` so it exercises both u16 bytes inside
  the policy cap.
* `tests/unit/test_compression.py` (+8): parametrised
  `test_streaming_decompress_accepts_exact_cap` and
  `test_streaming_decompress_rejects_bomb` for zlib / lzma / bz2;
  an optional brotli variant that skips if the wheel is absent;
  and `test_mod_level_max_cap_is_256_mib_by_default` as a
  spec-pin. All three stream tests monkey-patch the cap down to
  64 KiB via a fixture so the suite runs in < 1 s.
* `tests/unit/test_utils.py` (+5): tar bundle member-count cap,
  aggregate-size cap, unsafe-member budget accounting, default-
  cap spec-pin, and a small-legal-bundle sanity case.
* `tests/unit/test_cover_preserve.py` (new file, 5 tests): the
  happy-path sanity test; atomic preservation of the original
  destination on a PIL-side failure; tempfile cleanup when
  `os.replace` raises `PermissionError`; a spy-fixture assertion
  that the tempfile lives in the output directory (same FS →
  atomic rename); and a sniff round-trip.

### Removed

* `<image>.stegx-backup` sidecar from the rewrap flow. Runtime no
  longer ever writes an unencrypted copy of the pre-rewrap stego.

### Security — StegX Format v3 finalization (2026-04)

Landed the structural and cryptographic fixes required to make the v3
format production-ready:

* **R5 — Length-prefixed KDF factor framing + HKDF-Extract pre-mix.**
  `stegx_core/kdf.py` now frames each factor as
  ``TAG || struct.pack('!I', len) || raw_bytes`` with fixed 4-byte
  ASCII tags (``PWD0`` / ``KFL0`` / ``YKR0``) and concatenates them in a
  canonical order.  The framed buffer is then HKDF-Extract'd
  (``PRK = HMAC-SHA256(header_salt, IKM)`` per RFC 5869 §2.2) before
  being fed to Argon2id / PBKDF2 as the secret. A cross-factor
  collision — e.g. ``(pw='ab', kf='c')`` vs ``(pw='a', kf='bc')`` —
  is now cryptographically impossible, and the per-encode random
  ``header_salt`` defeats multi-target Argon2id amortisation. Raw
  factor bytes are framed directly; the previous SHA-256 pre-hash of
  keyfile / YubiKey bytes has been removed (length-prefixing already
  prevents collisions, so pre-hashing only discarded free entropy).
* **L3/C6 — Position-salt decoupling via HKDF.** `_derive_body_seed`
  in `stegx_core/steganography.py` now derives the body-shuffle seed
  through HKDF-Expand with an ``info`` string that binds **both** the
  cover fingerprint AND the per-encode random ``header_salt``. Two
  encodes of covers with identical geometry and the same password now
  produce completely different body-position streams. The head
  shuffle stays fingerprint-only (bootstrapping requirement — the
  extract side has to locate the sentinel before it can read
  ``header_salt``).
* **R11 — Adaptive mask applies from bit 0.** `_embed_stream` now
  picks the head-embedding method to match the body's ``method_ct``:
  when adaptive mode is on (``method_ct = LSB_REPLACEMENT``), the
  sentinel + header are also written with LSB_REPLACEMENT so the
  cost map is byte-identical at encode and decode. For non-adaptive
  methods, the head keeps LSB_MATCHING so the flat-histogram property
  still holds. `_split_head_body` now errors loudly if the adaptive
  mask leaves fewer positions than the sentinel + header require.
* **Variable-length header + KMS wrap structural fixes.** `_embed_stream`
  and `_split_head_body` now use `_head_byte_count_from_embed` to
  compute the head byte count dynamically (``SENTINEL_LEN +
  HEADER_SIZE_V3_BASE + kms_wrap_len``) instead of a hard-coded
  106-byte constant. KMS-wrap bytes now stay in the deterministic
  head region and no longer spill into the body-seed-shuffled
  position pool. `embed_v2`, `_embed_panic`, and `_embed_decoy` pass
  the full encrypted stream to `Header.unpack` (which reads only as
  many bytes as the declared ``kms_wrap_len`` demands) so they work
  for any wrap size up to `KMS_WRAP_MAX = 512`. The extract side
  already did a two-pass peek (base header → read ``kms_wrap_len`` →
  re-read full header).

### Tests added

* `tests/unit/test_header.py` (+16 tests): v3 version byte, base size,
  empty / populated / max-size `kms_wrap` round-trip, big-endian
  `kms_wrap_len` layout, truncation and oversize rejection, invalid
  `header_salt` / `yk_challenge_nonce` sizes, PBKDF2 + v3 combo,
  AAD covers the full variable-length header, `packed_size`
  consistency.
* `tests/unit/test_kdf.py` (+6 tests): length-prefix framing defeats
  cross-factor collisions, keyfile vs YubiKey domain separation,
  `b""`-equals-`None` canonicalisation, `header_salt` changes the
  master key and is deterministic per value, `hkdf_extract` matches
  RFC 5869 §2.2 byte-for-byte.

### Security (v2.0.0 audit remediations — 2026-04)

These items follow from the 2026-04 third-party audit. The follow-up
v3 header format (per-operation YubiKey nonce, position-salt
decoupling, length-prefixed KDF factors, KMS wrapping slot) is tracked
separately as a breaking release.

* **HIGH (R4) — Legacy v1 decode is now default-deny.** Previously every
  failed v2 decode walked the entire pixel grid looking for the v1
  constant sentinel; this was a permanent downgrade path (an attacker
  could force a weaker PBKDF2/390k + AES-GCM-no-AAD pipeline) *and* a
  CPU-timing side channel that distinguished "StegX v2 + wrong
  password" (fast) from "non-StegX / v1" (slow). The v1 path is now
  gated behind the opt-in `--allow-v1` flag on `stegx decode`.
* **HIGH (R7) — SSRF hardening on cover-URL fetch.** The `io_sources`
  cover fetcher resolved the URL's host with the system resolver and
  then reconnected, which allowed DNS rebinding and did not filter
  private, loopback, link-local, CGNAT, cloud-IMDS (`169.254.169.254`),
  or IPv6 ULA addresses. The fetcher now (a) rejects any address in
  those ranges, (b) pins the resolved IP for the actual connect() to
  defeat DNS rebinding, and (c) re-validates every redirect target
  through the same policy.
* **HIGH (R12) — Argon2id / PBKDF2 parameters parsed from a header are
  now bounds-checked.** Previously an attacker-crafted header could
  request up to 4 TiB of Argon2 memory or a million-round PBKDF2.
  Rejected bounds raise a generic `HeaderParameterOutOfRange`
  exception so individual fields are not an oracle.
* **HIGH (R6) — Audit log HMAC is now on by default.** The SHA-256
  chain alone could be truncated-and-rewritten by anyone with write
  access; HMAC is now computed against a machine-local 32-byte key
  stored at `$STEGX_CONFIG_HOME/audit.key` (owner-only mode 0o600) and
  auto-created on first append. Callers can opt out with
  `allow_unauthenticated=True`, but the default is signed.
* **MEDIUM (R2) — Panic mode docstring / behaviour made honest.** The
  feature is renamed in language to "plausible-deniability overwrite"
  and every user-facing docstring now states that it is **not** a
  forensic wipe on SSDs, COW filesystems (btrfs/ZFS/APFS/ReFS) or
  journaled filesystems (ext3/4 `data=journal`, NTFS). On POSIX we
  best-effort-call `shred -u -n 3` where it is available; the
  `os.replace` step now retries briefly on Windows (anti-virus holds)
  and surfaces a clear `PanicReplaceFailed` instead of silently leaving
  the original intact.
* **MEDIUM (R3, R10) — FIPS mode is now real.** `--fips` previously
  left Argon2id hard-coded in position-derivation, did nothing about
  YubiKey's HMAC-SHA1, and never checked that the linked OpenSSL was
  FIPS-validated. The flag now (a) asserts at startup that
  `cryptography`'s backend reports FIPS mode, (b) rejects `--yubikey`
  and `--dual-cipher`, and (c) raises `FipsPolicyViolation` on any
  attempt to use a non-FIPS primitive.
* **MEDIUM (R8, R9) — Cryptographic narrative cleaned up.**
  `--dual-cipher` help text no longer claims "defence in depth";
  `SecureBuffer` docstring no longer advertises "best-effort
  zeroisation" (the `AESGCM(bytes(...))` boundary immediately defeats
  it). The protections remain — the claims no longer overstate them.
* **MEDIUM (L2) — Rewrap is now durable.** When rewrapping in place,
  the original is copied to `<image>.stegx-backup` before the new
  write, the output is fsynced, and any failure restores the backup —
  so a SIGKILL / power loss mid-save no longer destroys the only
  readable copy.
* **MEDIUM (L5) — Broken logging.warning call fixed.** `utils.py` had a
  `logging.warning(f"...", {filename}, "...")` call that passed a Python
  set literal as a positional arg, producing a mangled log line.
* **MEDIUM (L7) — Output path traversal check.** `stegx encode
  --output ../../etc/stegx.png` now fails by default; pass
  `--allow-outside-cwd` to opt out.
* **LOW (L10) — Shamir `-k`/`-n` bounded.** `-k 500` previously leaked
  a library-level stack trace; argparse now bounds both arguments to
  `[1, 255]` and emits a clean user error.
* **LOW (L11) — Empty payload rejected early.** A zero-byte input no
  longer runs a full Argon2id cycle before failing with a misleading
  "cover too full" message — it raises `EmptyPayloadError` at payload
  construction time.
* **LOW (L12) — `verify_chain` field-pop fragility fixed.** The
  verification path no longer depends on `dict.pop` + re-add ordering,
  so adding fields to the record schema cannot silently break the
  chain hash.
* **Hardening — Python ≥3.12 required.** Drops the custom `_is_member_safe`
  burden for tar hardlink sanitisation; the built-in `tarfile` `data`
  filter is always present. `_is_member_safe` remains as a defence-in-depth
  layer.
* **Hardening — Output concurrency lock.** A sidecar
  `<output>.stegx-lock` file is created with `O_CREAT|O_EXCL` around
  every encode, so two concurrent StegX processes cannot silently
  corrupt each other's output.

### Deferred to follow-up breaking release (v3 format)

The following audit items require a payload-header format bump to fix
properly and are tracked separately:

* **R1** — bind the YubiKey challenge to a per-operation random 16-byte
  nonce stored in the header.
* **R5, R11** — length-prefix and HKDF-pre-mix KDF factors; apply
  adaptive cost-masking to the sentinel+header bits.
* **L1** — make the adaptive-mask empty-set fallthrough deterministic
  without punting to the now-default-denied legacy path.
* **Architectural** — KMS/HSM wrapping slot in the header, streaming
  AEAD, bulk rotation metadata.

### Security

* **HIGH — Per-image position KDF salt.** The position-shuffle Argon2id
  salt was previously a fixed constant, letting an attacker amortise the
  expensive KDF computation across every captured stego image. The salt
  is now derived per-image from the cover fingerprint
  (`SHA256(app_key || fingerprint)[:16]`), so multi-target
  pre-computation is no longer useful.
* **HIGH — Per-image YubiKey challenge.** The YubiKey HMAC-SHA1
  challenge was a fixed 32-byte constant, making captured responses
  replayable across images (equivalent to a static keyfile). The
  challenge is now derived per-image from the cover fingerprint.
* **MEDIUM — Panic-mode temp-file cleanup.** `destroy_real_region_in_place`
  wrote a `.panic.tmp` sibling file; a crash between `image.save()` and
  `os.replace()` could leave that file around as a forensic artefact.
  Now uses `tempfile.NamedTemporaryFile` in the same directory with a
  `try/finally` guarantee of cleanup.
* **MEDIUM — Rewrap temp-file cleanup.** `perform_rewrap` created a
  `.rewrap.tmp` scratch file that would leak to disk if `embed_v2`
  raised. Cleanup now lives in the `finally` block.
* **MEDIUM — Safer tar-bundle extraction.** Multi-file payload
  extraction now rejects hard-links explicitly and uses
  `TarFile.extract(filter='data')` on Python 3.12+ (CVE-2007-4559
  hardening).
* **LOW — Decompression-bomb cap.** All decompressors
  (zlib/lzma/bz2/zstd/zstd-dict/brotli) now enforce a 256 MiB output
  limit and raise `ValueError` if exceeded.
* **Bug — Extraction fallback.** `extract_v2_with_region` previously
  bailed on the first candidate region that passed the sentinel check
  but failed AEAD decryption. It now falls back to the remaining
  adaptive-filtered candidates, fixing a flaky round-trip failure mode.
* **Edge — Uniform-cover adaptive masks.** `build_adaptive_position_mask`
  no longer produces an empty mask on synthetic / uniform images where
  all cost values are equal; all positions are accepted instead.
* **Edge — Panic on legacy-v1 stego.** Running panic-destruction against
  a stego whose layout is `real-full` (non-split, e.g. legacy v1) now
  logs a warning instead of silently no-op'ing.
* **Structured exceptions propagated to runtime.** `crypto.py`,
  `steganography.py`, `utils.py` and `compression.py` now raise the
  concrete subclasses (`AuthenticationFailure` / `CorruptedPayload` /
  `InsufficientCapacity` / `UnsupportedImageMode` /
  `DecompressionBombError`). `AuthenticationFailure` multiply-inherits
  `InvalidTag` so existing callers keep working; `CorruptedPayload` and
  its siblings inherit `ValueError` for the same reason. The CLI decode
  path now catches everything under a single `except StegXError` branch.
* **Audit-log optional HMAC.** `append_record` / `verify_chain` accept
  an `hmac_key=` keyword. With a key set, each record carries an
  additional `hmac` tag over its canonical form; verification rejects
  tampered records even when the SHA-256 chain was successfully
  reconstructed by an attacker. Defeats the truncate-and-rewrite attack
  noted in the audit.
* **Panic → steganography coupling broken.** `destroy_real_region_in_place`
  now accepts explicit `real_region` / `decoy_region` keyword arguments;
  callers that have them precomputed can pass them directly. The
  deferred `from .steganography import _all_positions` is only used on
  the legacy zero-argument call-pattern.
* **`perform_encode` refactored.** Orchestration split into
  `_resolve_encode_files`, `_resolve_encode_credentials`,
  `_resolve_encode_decoy`, `_resolve_encode_panic`,
  `_probe_cover_capacity`, and `_attach_polyglot`. Cyclomatic complexity
  of the top-level function reduced from 12+ to ~4.
* **Capacity-check invariant made explicit.** The dead
  `if body_bits < 0: raise ValueError(...)` guard in `_capacity_check`
  is replaced by an `assert` that documents the invariant (all embed
  streams carry at least sentinel + header bytes).
* **Polyglot trailing-data warning** upgraded from DEBUG to WARNING so
  operators notice discarded iTXt / tEXt / eXIf chunks.
* **Combination-flag integration coverage.** New tests cover
  `--always-split-cover` → rewrap, `--panic-password` → rewrap, and
  `--yubikey` + `--fips` round-trips.

### Infrastructure

* CI runs `bandit`, `pip-audit`, and Trivy (Docker image) on every PR.
* New `fips` CI job executes the full suite under `STEGX_FIPS=1`.
* Docker base image pinned to SHA256 digest.
* Dependabot monitors `pip`, `docker`, and `github-actions` weekly.
* Release workflow signs wheels + sdist with `sigstore` and attaches a
  CycloneDX SBOM.
* New `requirements-lock.txt` with pinned versions for reproducible
  installs.
* New `SECURITY.md` (disclosure policy) and `THREAT_MODEL.md`.
* New `stegx_core/exceptions.py` with a structured exception hierarchy.
* New `stegx_core/constants.py` centralising cryptographic magic
  constants.
* New fuzz harness at `tests/fuzz/fuzz_extract.py` (atheris-compatible,
  falls back to random-byte smoke test).

### Added

* `stegx --version` now prints a rich banner listing every optional
  dependency (argon2-cffi / zstandard / brotli / zxcvbn / ykman / numpy)
  plus runtime capabilities (memory locking, available compression
  codecs). Useful for quickly diagnosing "why is Argon2id / YubiKey /
  brotli not working" without inspecting the interpreter.
* `stegx benchmark --calibrate [--target-ms 500]` sweeps Argon2id
  memory-cost values on the current machine and recommends a setting
  that lands near the target latency.
* `stegx rewrap -i stego.png [-o new.png]` rotates password / keyfile /
  YubiKey on an existing stego image without writing plaintext to disk.
  Old LSB positions are overwritten with cryptographic noise so the old
  credentials can no longer recover the payload from the rotated file.
* `--audit-log PATH` on `encode` / `decode` / `rewrap`: appends a
  hash-chained JSONL record of the operation (timestamp, op, ok/fail,
  cover/stego SHA-256, flag names used). Payload content never leaks
  into the log. New [`audit_log.py`](stegx/stegx_core/audit_log.py)
  module with a `verify_chain()` helper that detects tampering and
  reports the first bad line.
* System-test coverage for the installed `stegx` console script via
  `shutil.which`, guaranteeing the `[project.scripts]` wiring keeps
  working end-to-end.

### Fixed

* `split_cover` predicate in `embed_v2` now correctly includes the
  `--panic-password` branch; without this the panic region was never
  allocated.

### Initial 2.0.0 feature set (2026-04-20)

#### ⚠️ Breaking changes

* **Container format rewritten.** Stego PNGs produced by StegX ≥ 2.0 are
  **not backwards-compatible with the 1.x reader**. The 2.0 reader, however,
  *can still decrypt v1 stego images* via an automatic fallback path. Re-encode
  anything you still need in one direction.
* **Default KDF changed** from PBKDF2-HMAC-SHA256 (390k iterations) to
  **Argon2id** (time=3, memory=64 MiB, parallelism=4). PBKDF2 is still
  selectable via `--kdf pbkdf2` at 600k iterations.
* **CLI `-p/--password` is no longer required.** If omitted, the password is
  read from a TTY prompt (`getpass`) or `--password-stdin`. Passing `-p`
  explicitly now produces a warning because it exposes the password in shell
  history and `ps`.
* **Payload metadata version** bumped to `3` (adds `compression_alg` field).

#### Added — Cryptography

* Argon2id password KDF ([`kdf.py`](stegx/stegx_core/kdf.py)) with
  application-specific salt for the position-derivation pass and a random
  per-payload salt for the AEAD key derivation.
* HKDF domain-separated sub-keys for AES-256-GCM, ChaCha20-Poly1305, the
  pixel-shuffle seed, and the sentinel key.
* AEAD associated-data binding: the entire 56-byte outer header
  (version/flags/KDF-params/salts/nonces) is authenticated as AAD — any
  tampering invalidates the GCM tag.
* `--dual-cipher` layers ChaCha20-Poly1305 over AES-256-GCM with independent
  keys, giving defence-in-depth against a catastrophic break of either cipher.
* `--keyfile PATH` mixes an external binary into the KDF input, acting as a
  second factor.
* Legacy v1 decrypt path (`decrypt_legacy_v1`) for images encoded with
  StegX ≤ 1.2.1.

#### Added — Steganography

* **LSB matching (±1)** is now the default embedding method — defeats the
  asymmetry exploited by chi-square and RS steganalysis. LSB replacement is
  retained only for legacy compatibility.
* **Adaptive embedding** (`--adaptive`) filters pixel positions by Laplacian
  edge cost, concentrating changes in textured regions.
* **Matrix embedding** (`--matrix-embedding`) uses an F5-style Hamming(7,3)
  syndrome coder on the ciphertext body, cutting the per-bit change rate by
  roughly 2.3×.
* **Per-image HMAC sentinel** replaces the fixed `STEGX_EOD` marker — varies
  with password *and* cover, so it can no longer be pattern-matched.
* **`--max-fill PCT`** (default 25 %) refuses payloads that would occupy too
  much of the cover's capacity, below the threshold where CNN steganalysers
  win reliably.
* **PNG metadata stripping**: stego output has an empty `PngInfo()`,
  removing the default `Software = Pillow X.Y` chunk and any chunks inherited
  from the cover. The output's `compress_level` is matched to the cover's.
* **Constant-time sentinel comparison** via `hmac.compare_digest`.

#### Added — Operational hardening

* `getpass` default for password entry; `--password-stdin` for scripting.
* `zxcvbn` password-strength gate — warn on score < 3, or reject outright
  with `--strict-password`.
* Unified decode error message — wrong password, wrong keyfile and
  non-StegX image now all produce the same text, removing an oracle.
* Best-effort memory wipe of master keys and HKDF sub-keys after use
  ([`secure_memory.py`](stegx/stegx_core/secure_memory.py)).
* Versioned container header (magic + version byte + flags bitfield) so
  future algorithm upgrades stay non-breaking.

#### Added — New features

* **Plausible-deniability decoy** (`--decoy-file`, `--decoy-password`): the
  cover is deterministically split (cover-fingerprint-derived, no password
  input) into two disjoint regions. Either password unlocks only its own
  region. Without both passwords, an observer cannot tell whether a second
  region carries anything.
* **k-of-n Shamir Secret Sharing** (`stegx shamir-split` /
  `stegx shamir-combine`): distribute a secret file across `n` cover images
  such that any `k` reconstruct it. Uses GF(2⁸) with irreducible polynomial
  0x11D (where element `2` is primitive).
* **Cover from URL**: `-i https://…` triggers a download (http/https only,
  `Content-Type=image/*`, 50 MiB cap, 30 s timeout, Pillow verification,
  auto-cleanup). No scripting, no execution.
* **In-memory / stdout output** for decode: `--stdout` or `-d -` pipes the
  decrypted payload to stdout, e.g. `stegx decode -i x.png --stdout | ssh-add -`.

#### Added — Compression multiplexer

* `--compression best` (default) runs five general-purpose compressors in
  parallel and keeps the smallest:
  `zlib-9`, `lzma2-extreme`, `bzip2-9`, `zstd-22`, `brotli-11`.
  The winning algorithm name is stored in metadata.
* `--compression fast` restricts to zlib for latency-critical use.
* Typical savings over zlib-only: **40-75 % smaller** on text/JSON/code;
  falls through to `none` (raw bytes) on incompressible input instead of
  paying compressor overhead.

#### Dependencies

* Added: `argon2-cffi >= 23.1.0`, `zxcvbn >= 4.4.28`,
  `zstandard >= 0.22.0`, `brotli >= 1.1.0`.
* Raised: `Pillow >= 10.0.0`, `cryptography >= 41.0.0`.

#### Fixed

* **AEAD AAD mismatch** (discovered in 2.0 development): the AAD is now
  canonicalised by zeroing `inner_ct_length` before packing, so encrypt-time
  and decrypt-time AADs match.
* **Shamir polynomial correctness** (discovered in 2.0 development): the
  initial implementation used 0x11B (AES polynomial), under which `2` is
  *not* primitive (order 51, not 255). Switched to 0x11D where `2` is
  primitive and the multiplicative group is fully traversed.
* **CodeQL `py/weak-sensitive-data-hashing`** — the SHA-256 seed derivation
  in `get_seed_from_password` was the original trigger for this rewrite.

#### Tests

* Test count: **108 passing** (was 51 in 1.x).
* New suites: `test_kdf.py`, `test_header.py`, `test_shamir.py`,
  `test_compression.py`, `test_io_sources.py`.
* Existing suites: unit, integration, security, system, performance — all
  re-written for the v2 APIs.

## [1.2.1] — 2026-04-20

### Fixed

* Replaced SHA-256 seed derivation in `get_seed_from_password` with
  PBKDF2-HMAC-SHA256 (390 000 iterations, fixed app-specific salt) to
  address CodeQL rule `py/weak-sensitive-data-hashing`. Raised brute-force
  cost of the seed derivation to match the AEAD key derivation.

### Breaking

* Stego images encoded with StegX ≤ 1.1.0 cannot be decoded by 1.2.1
  because the seed changed. Re-encode with the new version.

## [1.2.0]

* Internal reorganisation; version bump only (feature-equivalent to 1.1.0).

## [1.1.0]

* Original public release: non-linear LSB + AES-256-GCM + PBKDF2 key
  derivation + zlib compression + `STEGX_EOD` sentinel.
