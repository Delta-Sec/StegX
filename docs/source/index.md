# StegX

**Authenticated LSB steganography with Argon2id, AES-GCM + ChaCha20-Poly1305,
Shamir quorum and plausible-deniability panic mode — version {{ release }}.**

StegX hides files inside PNG images using password-shuffled LSB embedding and
authenticated encryption.  It is a ground-up security rewrite built around a
versioned container format, Argon2id key derivation, domain-separated HKDF
sub-keys, LSB-matching (±1) embedding that defeats chi-square steganalysis,
and optional ChaCha20-Poly1305 dual-cipher, F5-style matrix embedding,
adaptive cost-map filtering, keyfile 2FA, YubiKey challenge-response,
plausible-deniability decoy payloads, panic-mode destructive decode, and
k-of-n Shamir secret sharing across multiple cover images.

```{toctree}
:caption: Getting started
:maxdepth: 2

cli/index
packaging/index
```

```{toctree}
:caption: Security
:maxdepth: 2

security/threat-model
security/evaluation-report
```

```{toctree}
:caption: Container format
:maxdepth: 2

format/index
```

```{toctree}
:caption: Testing
:maxdepth: 2

testing/suite
testing/coverage
testing/test-case-explanations
```

```{toctree}
:caption: Python API
:maxdepth: 2

api/index
```

## Indices and tables

* {ref}`genindex`
* {ref}`modindex`
* {ref}`search`
