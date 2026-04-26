# Container format

```{note}
This section is scaffolded. Migrate the v2 / v3 header diagrams from the
repo-root `README.md` and the "StegX Format v3 finalization" section of
`CHANGELOG.md` (2.0.0 entry) here in a follow-up PR.
```

## v3 header (shipped in 2.0.0)

| Field | Size | Notes |
|---|---|---|
| `magic`            | 1 B | 0x58 |
| `version`          | 1 B | 0x03 |
| `kdf_id`           | 1 B | 0x02 Argon2id, 0x01 PBKDF2 |
| `flags`            | 1 B | keyfile / dual-cipher / yubikey / adaptive / panic |
| `kdf_params`       | 8 B | `time_cost, memory_kib, parallelism` (packed) |
| `header_salt`      | 16 B | random per encode — HKDF-Extract pre-mix |
| `aes_nonce`        | 12 B | |
| `chacha_nonce`     | 12 B | unused unless FLAG_DUAL_CIPHER |
| `yk_challenge_nonce` | 12 B | unused unless FLAG_YUBIKEY |
| `kms_wrap_len`     | 2 B | big-endian, ≤ 512 |
| `inner_ct_length`  | 4 B | AAD-canonicalised to 0 before pack |
| `kms_wrap`         | N B | variable, 0 … 512 |

The full header (base + `kms_wrap`) is authenticated as AEAD associated data.
