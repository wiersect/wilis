# Security Policy & Threat Model

## Scope & Honest Disclaimer

**Wilis** is an independent, custom-designed cryptographic suite created for cryptographic engineering research, education, and personal experimentation.

- It is **not** a drop-in replacement for NIST/IETF-standardized cryptography in regulated or mission-critical production systems.
- Although Wilis incorporates modern cryptographic engineering practices (duplex sponge AEAD, 256-bit capacity, constant-time bitsliced/ARX arithmetic without table lookups, hybrid memory-hard KDF, chunked anti-truncation streaming, volatile memory zeroization, and built-in cryptanalysis auditing), **no newly invented cipher should be assumed as vetted as AES-GCM, ChaCha20-Poly1305, or Argon2id** without years of independent third-party cryptanalysis.

## Defenses Implemented

| Threat | Mitigation in Wilis |
| :--- | :--- |
| **GPU / ASIC Offline Brute-Force** | Hybrid memory-hard `WilisKDF` v2 requiring 16–64 MiB RAM per guess + optional 2FA `--keyfile` |
| **Cache-Timing Side Channels** | Zero S-Box lookup tables; constant-time tag comparison (`ct_eq`); branchless, division-free constant-time Module-LWE & `GF(2^8)` arithmetic; data-independent Pass 0 in `WilisKDF` |
| **Ciphertext Malleability / Bit Flips** | 256-bit keyed authentication tag (`WilisAEAD`) verified before releasing plaintext; Fujisaki-Okamoto IND-CCA2 implicit rejection in `WilisKEM`; canonical Base64 & 13-bit packing |
| **Header / Parameter Downgrade** | Full header bytes (including KDF cost, salt, nonce, chunk size) cryptographically bound into AAD |
| **File Truncation / Chunk Reordering** | `WILS` v2 per-chunk nonce derivation + `(header_digest, chunk_index, is_final)` binding |
| **Archive Traversal / Symlink Escape** | `WilisDir` rejects `..`, absolute/colon/reserved Windows paths, case-insensitive & file-vs-dir collisions, trailing garbage, and existing symlinks; extracts with `0600`/`0700` Unix modes |
| **Secret Leakage in RAM / Disk / Shell** | Volatile zeroization (`write_volatile` + `compiler_fence`) on drop & error paths, CSPRNG `O_EXCL` atomic temp files (`sync_all` + rename, immune to predictable `.tmp` symlink attacks), owner-only `0600` Unix permissions on `.wsk`/`.wks`/vault/decrypted outputs, hidden `--pass-prompt` |
| **Nonce Collision** | 192-bit random nonces read from native OS CSPRNG (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows) |

## Reporting Cryptanalytic Findings

Cryptanalysis, differential/linear trail discoveries, implementation bugs, and side-channel reports are warmly welcomed! Please open an issue or submit a security advisory in the [GitHub repository](https://github.com/wiersect/wilis/issues) with:
1. Affected component (`WilisPerm-384`, `WilisAEAD`, `WilisKDF`, `WILS` stream, or CLI).
2. A reproducible test case or proof-of-concept.
3. Observed vs. expected security property.
