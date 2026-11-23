# Changelog

All notable changes to **Wilis** are documented in this file.

## [0.2.0] - 2026-11-23

### Added
- **Core Permutation (`WilisPerm-384`)**: 384-bit hybrid ARX + bitsliced `Chi-5`/`Feistel-6` + invertible 3-tap diffusion permutation with 32 transparent prime fifth-root constants and exact inverse verification.
- **Authenticated Encryption (`WilisAEAD`)**: Duplex sponge AEAD with 256-bit key, 192-bit nonce, 256-bit tag, 256-bit capacity, key whitening, and key-commitment protection.
- **Hybrid Memory-Hard KDF (`WilisKDF` v2)**: 16 MiB (`interactive`), 32 MiB (`high`), and 64 MiB (`paranoid`) presets combining data-independent Pass 0 with data-dependent Passes `1..T` and optional 2-factor `--keyfile` mixing.
- **Chunked Streaming AEAD (`WILS` v2)**: Constant-memory 64 KiB chunked file encryption resisting truncation, reordering, duplication, and trailing-data attacks.
- **Sponge Hash (`WilisHash-256`)**: Incremental and one-shot 256-bit cryptographic hash.
- **Scientific Cryptanalysis Audit (`wilis audit`)**: Automated per-round SAC (1–16), BIC, exact `Chi-5` DDT/LAT analysis, and NIST-style keystream randomness battery.
- **Zero-Dependency CLI & Utilities**: Hidden interactive password prompts (`--pass-prompt`), constant-time comparisons, volatile zeroization, Base64/Hex codecs, and live benchmarks (`wilis bench`).
- **Flat Modular Layout**: Clean root-level module directories (`core/`, `aead/`, `kdf/`, `hash/`, `format/`, `stream/`, `audit/`, `utils/`, `cli/`, `tests/`) with full technical specification (`SPECIFICATION.md`), security policy (`SECURITY.md`), and GitHub Actions CI.
