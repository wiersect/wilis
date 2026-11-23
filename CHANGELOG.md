# Changelog

All notable changes to **Wilis** are documented in this file.

## [0.4.1] - 2026-11-23

### Bug Fixes & Full-Codebase Security Audit Pass
- **Cryptographic Domain Separation (`xof/sponge_xof.rs`)**: Fixed empty-vs-non-empty domain label collision by unconditionally length-prefixing `domain_label` (absorbing `0u64` when empty). Fully compatible with all existing non-empty labels (`WilisKEM`, `WilisRatchet`).
- **Base64 Canonical Padding (`utils/base64.rs`)**: Enforced strict RFC 4648 zero trailing padding bits (`(v1 & 0x0F) == 0` for `==`, `(v2 & 0x03) == 0` for `=`), eliminating Base64 malleability.
- **Shamir Share Validation (`split/shamir.rs`)**: Fixed missing `index <= total` bounds check in `Share::from_bytes`, enforced `s.total == total`, and verified all extra shares (`shares[k..]`) lie on the exact reconstructed Lagrange polynomial so corrupted backup shares are never silently accepted.
- **Ratchet Counter Overflow Protection (`ratchet/session.rs`)**: Replaced `wrapping_add` on `send_counter` with `checked_add`, rejected `packet.counter == u64::MAX` before `counter + 1` in `decrypt_packet` (blocking replay wrap-around), and zeroized `temp_chain`/`c_a`/`c_b`/`msg_key` stack intermediates.
- **In-Place Truncation & Clobber Prevention (`cli/file_cmd.rs`, `cli/kem_cmd.rs`, `cli/sign_cmd.rs`, `archive/pack.rs`)**: Blocked `--in == --out` across file encryption/decryption, public-key, and signing commands (preventing overwriting input or `.wsk` secret key files), prevented placing a directory archive inside its own source directory, and switched file outputs to atomic sibling `.tmp` writes with error cleanup so existing files are never clobbered on authentication failure or wrong passphrases.
- **Owner-Only Secret Key Permissions & Vault Hardening (`utils/zeroize.rs`, `cli/sign_cmd.rs`, `cli/kem_cmd.rs`, `vault/store.rs`)**: Added `write_secret_file` enforcing strict `0600` (`rw-------`) Unix permissions on both newly created and overwritten `.wsk`, `.wks`, and vault files; fixed 32-bit length-addition overflow & empty-key handling in `Vault::from_bytes`; guaranteed vault secret zeroization on overwrite, delete, and error paths.
- **WOTS+ Stateful Leaf Safety (`sign/keypair.rs`)**: Moved OS RNG randomizer generation before incrementing `next_index` (so RNG failure never burns a one-time signature leaf) and validated `next_index <= 2^height` during `SigningKey::from_bytes`.
- **Deep Memory Zeroization Sweep**: Added volatile memory zeroization across `WilisHash` drop buffer, `WilisAEAD` finalize/decrypt stack intermediates, `WilisMAC` tag halves, `WilisKDF` padded passphrase block & stack key copy, `WilisKEM` CBD entropy & ephemeral secret polynomials (`e`, `r`, `e1`, `e2`, `m_poly`, `su`, `diff`, `ss`), `WOTS+` secret elements, streaming chunk buffers, `WilisDir` packed/decrypted buffers, `prompt.rs` confirm passphrase (with constant-time comparison) & keyfile read buffer, C-FFI secret buffers, and CLI handlers.
- **Audit Edge-Case & Dynamic Versioning Fixes (`audit/`, `cli/bench_cmd.rs`, `cli/args.rs`)**: Guarded `analyze_keystream_randomness(sample_bytes < 256)` and `analyze_bic(0)` against index panic / division by zero, removed dead `flip_counts` and dead `_as_const_buf` helper in `bindings/python/wilis_py.py`, made `wilis bench` return an error on bijectivity failure, and switched CLI/audit headers to `env!("CARGO_PKG_VERSION")`.

## [0.4.0] - 2026-11-23

### Added
- Post-Quantum Module-LWE KEM & Hybrid Public-Key Encryption (`WilisKEM` / `WPKE`), Forward-Secret Messaging Ratchet (`WilisRatchet`), `WilisXOF`, `WilisMAC`, 6-part `wilis audit`, expanded C/Python FFI, and adversarial fuzz test suite.

## [0.3.0] - 2026-11-23

### Added
- Post-Quantum Digital Signatures (`WilisSign` WOTS+ Merkle), Shamir's Secret Sharing (`WilisSplit`), Encrypted Directory Archiver (`WilisDir`), Encrypted Secret Vault (`WilisVault`), native Windows CSPRNG/prompts, C-FFI & Python bindings, and multi-OS CI/Release builds.

## [0.2.0] - 2026-11-23

### Added
- Core `WilisPerm-384`, `WilisAEAD`, hybrid memory-hard `WilisKDF` v2 (16–64 MiB + 2FA keyfile), `WILS` v2 chunked streaming, `WilisHash-256`, scientific `wilis audit`, flat root layout, `SPECIFICATION.md`, `SECURITY.md`, and GitHub Actions CI.
