# StegX Threat Model

> **Note:** The original repo-root `THREAT_MODEL.md` was not tracked in git
> and its content was lost during the v3 repository restructure. This page
> is a fresh reconstruction derived from the `CHANGELOG.md` 2.0.0 section
> and the audit-remediation notes. Re-work as needed.

## Assets under protection

1. **Payload confidentiality** — the file embedded inside a StegX PNG must
   remain secret against attackers who obtain the stego image plus arbitrary
   auxiliary information short of the passphrase (and, when enabled,
   the keyfile / YubiKey response).
2. **Payload integrity** — any bit-level tampering of the stego image must
   cause decode to fail closed, not produce attacker-controlled plaintext.
3. **Cover indistinguishability** — a stego image must be statistically
   indistinguishable from an unmodified PNG of the same cover under
   standard LSB steganalysis (chi-square, RS, SPA, CNN-based).
4. **Plausible deniability** — the decoy / panic-mode machinery must make
   it computationally infeasible for an observer to prove whether a
   second (real) payload exists.

## Adversaries

| Capability | In scope |
|---|---|
| Passive observation of the stego image | ✅ |
| Passive observation of the cover + stego pair | ✅ |
| Modifying the stego image on the wire | ✅ |
| Running steganalysis toolkits (StegExpose, aletheia, SRNet, etc.) | ✅ |
| Coercing the holder to reveal a password | ✅ (panic mode) |
| Host RAM scraping during `stegx encode/decode` | ⚠️ Best-effort `SecureBuffer` wipe only |
| Side-channel (timing, EM, power) attacks on the device running `stegx` | ❌ Out of scope |
| Breaking AES-256-GCM / Argon2id / ChaCha20-Poly1305 cryptographically | ❌ Out of scope |

## Cryptographic primitives (StegX 2.0.0 / v3 format)

| Layer | Primitive |
|---|---|
| Password KDF | Argon2id (time=3, memory=64 MiB, parallelism=4), PBKDF2 fallback at 600 k iterations |
| Factor framing | Length-prefixed `PWD0`/`KFL0`/`YKR0` tags, HKDF-Extract pre-mix with per-encode `header_salt` |
| Sub-key derivation | HKDF-SHA256 domain-separated for AES-GCM / ChaCha20-Poly1305 / sentinel / shuffle seed |
| AEAD | AES-256-GCM (primary), optional ChaCha20-Poly1305 layered via `--dual-cipher` |
| AAD binding | Full variable-length v3 header (90 B base + ≤512 B KMS wrap) |
| Position shuffle | SHA-256(fingerprint ‖ HKDF-Expand(master, info=fingerprint ‖ header_salt)) |
| Sentinel | HMAC-SHA256(sentinel_key, cover_fingerprint)[:16], constant-time compared |

## Known residual risks

1. **RAM coldboot / swap leak** of the decrypted payload before the
   `SecureBuffer` wipe — best-effort only on non-mlock platforms.
2. **Cover-encoder fingerprint** for custom PNG encoders that differ from
   Pillow's defaults — StegX preserves cover parameters and strips
   metadata but cannot reproduce unknown encoder quirks.
3. **Steganalysis breakthrough** — if a future deep-learning detector
   outperforms the current SRNet baseline at 25 % embed rate, the
   `--max-fill` default ceiling may need to be lowered.

See `CHANGELOG.md` (2.0.0 release section) for the full list of
audit-remediation fixes and their justifications.
