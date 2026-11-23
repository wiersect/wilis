# Changelog

All notable changes to **Wilis** are documented in this file.

## [0.4.0] - 2026-11-23

### Added
- **Post-Quantum Public-Key Encryption & KEM (`WilisKEM` — `kem/`)**: Original Module-LWE (`k = 3`, `N = 256`, `q = 7681`, `CBD_2`, `49σ` noise margin) with exact 13-bit canonical packing, Fujisaki-Okamoto IND-CCA2 constant-time implicit rejection, and hybrid `WPKE` v1 file encryption (`wilis kem-keygen`, `pub-encrypt`, `pub-decrypt`).
- **Forward-Secret Messaging Ratchet (`WilisRatchet` — `ratchet/`)**: Bidirectional symmetric chain ratchet destroying prior chain keys after every message, with bounded out-of-order delivery (`MAX_SKIP_WINDOW = 64`), speculative verification (preventing forged-packet state corruption), and replay rejection.
- **Extendable-Output Sponge (`WilisXOF` — `xof/`)**: Domain-separated arbitrary-length XOF and deterministic PRNG powered by `WilisPerm-384`.
- **Keyed 256-bit MAC & Subkey Derivation (`WilisMAC` — `mac/`)**: Length-extension-immune keyed sponge MAC (`wilis mac`, `mac-verify`), domain-separated `derive_subkey`, and `wilis rand`.
- **Expanded 6-Part Scientific Audit (`audit/`)**: Added `[5/6]` 256-bit Related-Key Sensitivity test on `WilisAEAD` and `[6/6]` live Post-Quantum `WilisKEM` CCA2 & implicit rejection audit.
- **Expanded C-FFI & Python Bindings**: Exported `wilis_mac_256`, `wilis_xof_derive`, `wilis_kem_keygen`, `wilis_kem_encapsulate`, and `wilis_kem_decapsulate` over `libwilis` and `bindings/python/wilis_py.py` (upgraded to `c_void_p` buffers for strict embedded-NUL safety).
- **Adversarial Parser Fuzz Suite (`tests/bug_audit_fuzz.rs`)**: Fuzzes all 16 binary/text parsers across 300+ malformed, truncated, and overflow inputs to guarantee zero panics.

### Security & Bug Fixes (Audit Pass)
- Added volatile memory zeroization `Drop` implementations for `Vault` secret entries (`vault/store.rs`) and CLI `AuthInput` passphrases (`cli/args.rs`).
- Enforced `MAX_ARCHIVE_FILES` cap and strict post-archive EOF trailing-garbage rejection in `WilisDir` (`archive/unpack.rs`).
- Hardened `combine_shares` in `WilisSplit` (`split/shamir.rs`) against degenerate manually constructed `Share` structs (`threshold < 2` or empty data).

## [0.3.0] - 2026-11-23

### Added
- Post-Quantum Digital Signatures (`WilisSign` WOTS+ Merkle), Shamir's Secret Sharing (`WilisSplit`), Encrypted Directory Archiver (`WilisDir`), Encrypted Secret Vault (`WilisVault`), native Windows CSPRNG/prompts, C-FFI & Python bindings, and multi-OS CI/Release builds.

## [0.2.0] - 2026-11-23

### Added
- Core `WilisPerm-384`, `WilisAEAD`, hybrid memory-hard `WilisKDF` v2 (16–64 MiB + 2FA keyfile), `WILS` v2 chunked streaming, `WilisHash-256`, scientific `wilis audit`, flat root layout, `SPECIFICATION.md`, `SECURITY.md`, and GitHub Actions CI.
