# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report them privately:

1. **Email:** Send details to **ayhamasfoor1@gmail.com** with the subject
   `[StegX Security] <brief description>`.
2. **GitHub Security Advisories:** Use the
   [private vulnerability reporting](https://github.com/Delta-Sec/StegX/security/advisories/new)
   feature on this repository.

### What to include

- A clear description of the vulnerability.
- Steps to reproduce (PoC code or a minimal example).
- The version(s) of StegX affected.
- The impact you believe the vulnerability has.

### Response timeline

- **Acknowledgement:** within 72 hours.
- **Triage + severity assessment:** within 7 days.
- **Fix or mitigation:** within 30 days for HIGH/CRITICAL; 90 days for
  MEDIUM/LOW.

### Disclosure policy

We follow **coordinated disclosure**: you agree not to publish the
vulnerability until a fix is released or 90 days have elapsed, whichever
comes first. We will credit you in the advisory unless you prefer to
remain anonymous.

## Security Design Summary

StegX v2 uses the following cryptographic pipeline:

- **KDF:** Argon2id (default) or PBKDF2-HMAC-SHA256 (FIPS mode).
- **AEAD:** AES-256-GCM, optionally layered with ChaCha20-Poly1305.
- **Key hierarchy:** HKDF-SHA256 derives sub-keys for AES, ChaCha20,
  pixel-shuffle seed, and per-image sentinel from a single master key.
- **Position salt:** per-image (derived from cover fingerprint) to prevent
  multi-target amortisation of the Argon2id computation.
- **YubiKey challenge:** per-image (derived from cover fingerprint) so a
  captured HMAC-SHA1 response cannot be replayed across images.
- **Sentinel:** HMAC-SHA256 of the sentinel key bound to the cover
  fingerprint; verified with constant-time comparison.
- **Header AAD:** the entire 56-byte outer header is bound as associated
  data to the AEAD, preventing algorithm-downgrade attacks.

## Supply Chain

- Docker base images are pinned to SHA256 digests.
- CI runs `bandit`, `pip-audit`, and Trivy on every PR.
- Releases are signed with [sigstore](https://sigstore.dev) and include
  a CycloneDX SBOM.
