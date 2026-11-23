# Changelog

All notable changes to **Wilis** are documented in this file.

## [0.3.0] - 2026-11-23

### Added
- **Post-Quantum Digital Signatures (`WilisSign` — `sign/`)**: Stateful tweaked `WOTS+` (`w = 16`, 67 chains) + Merkle Tree (`height = 2..=10`) built strictly from `WilisHash-256`, with randomized message hashing, integrity-protected `WSK1`/`WPK1` key files, and atomic leaf-counter updates preventing one-time key reuse.
- **Shamir's Secret Sharing (`WilisSplit` — `split/`)**: Information-theoretic `K`-of-`N` threshold secret splitting over branchless, constant-time `GF(2^8)` with built-in 64-bit `WilisHash-256` secret commitment checks and portable `wilis-share-v1:` text encoding.
- **Encrypted Directory Archiver (`WilisDir` — `archive/`)**: Custom deterministic `WDIR` v1 recursive folder archiver streamed directly through `WILS` v2 chunked encryption (hiding filenames and hierarchy) with strict Zip-Slip / path-traversal validation.
- **Encrypted Local Secret Vault (`WilisVault` — `vault/`)**: Atomic encrypted key-value secret store (`WVLT` v1) supporting passphrase + 2FA keyfile protection (`wilis vault init|set|get|list|del`).
- **Native Windows Support**: Cross-platform OS CSPRNG (`BCryptGenRandom` on Windows, `/dev/urandom` on Unix) and Win32 `SetConsoleMode` hidden passphrase prompts.
- **C-FFI & Python Bindings (`ffi/`, `include/wilis.h`, `bindings/python/wilis_py.py`)**: Exported `libwilis` shared/static C-ABI library plus a zero-dependency Python 3 `ctypes` wrapper.
- **Multi-OS CI & Release Automation**: Automated testing, auditing, Python FFI verification, and release packaging across **Linux x86_64**, **macOS ARM64**, and **Windows x86_64**.

## [0.2.0] - 2026-11-23

### Added
- Core `WilisPerm-384` permutation, `WilisAEAD`, hybrid memory-hard `WilisKDF` v2 (16–64 MiB + 2FA keyfile), `WILS` v2 chunked streaming, `WilisHash-256`, scientific `wilis audit` suite, flat root layout, formal `SPECIFICATION.md`, `SECURITY.md`, and GitHub Actions CI.
