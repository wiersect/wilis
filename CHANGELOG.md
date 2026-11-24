# Changelog

All notable changes to **Wilis** are documented in this file.

## [0.4.5] - 2026-11-24

### Bug Fixes & Deep Protocol / Filesystem / CLI Hardening (Round 5)
- **Canonical `WILS` v2 Stream Framing (`stream/decrypt_stream.rs`)**: Enforced `ct_len == chunk_size` on all non-final chunks (`is_final == false`), blocking non-canonical chunk boundaries and zero-byte non-final chunk CPU DoS attacks.
- **Case-Insensitive Collision, File-vs-Dir & Permission Hardening in `WilisDir` (`archive/unpack.rs`, `archive/pack.rs`)**: Rejected case-folding duplicate paths (`Secret.txt` vs `secret.txt` on macOS APFS / Windows NTFS) and file-vs-directory prefix conflicts (`a/b` vs `a/b/c.txt`); enforced owner-only `0600` file / `0700` directory Unix modes + `sync_all()` on extraction; rejected existing directory paths as archive output targets up front.
- **`WilisSign` Merkle Root Consistency Verification (`sign/keypair.rs`)**: Verified `root == build_merkle_tree(secret_seed, pub_seed, height)` in constant time inside `SigningKey::from_bytes`, preventing faulted/corrupted `WSK1` secret keys from burning one-time WOTS+ leaves on unverifiable signatures.
- **Terminal Escape Injection & Bounds Hardening in `WilisVault` (`vault/store.rs`)**: Rejected control characters (newlines, NUL, ANSI escapes) in vault secret names across `Vault::set` and `Vault::from_bytes` (preventing terminal spoofing in `vault list`) and enforced explicit key/value length caps.
- **Key-Clobber Prevention, Duplicate-Flag Rejection & `split-key` Secret Zeroization (`cli/args.rs`, `cli/kem_cmd.rs`, `cli/sign_cmd.rs`)**: Blocked overwriting `.wkp`/`.wks` keys in `pub-encrypt`/`pub-decrypt`, blocked overwriting 2FA `--keyfile` via `--out`/`--file`, rejected empty/directory `--out` prefixes in `kem-keygen`/`sign-keygen`, rejected duplicate single-value CLI flags across all commands (preventing flag-shadowing injection), and wrapped `--secret` in `ZeroizeStr` in `parse_split_key`.
- **32-Bit AAD Capacity Overflow Guards & Regression Suite (`stream/chunk_nonce.rs`, `format/container.rs`, `kem/hybrid.rs`, `ratchet/session.rs`, `tests/known_answer_vectors.rs`)**: Used `saturating_add` in AAD capacity calculations and added `regression_v045_audit_fixes_verified` (**40 / 40 tests**).

## [0.4.4] - 2026-11-24

### Bug Fixes & Atomic File-Security Hardening (Round 4)
- **Eliminated Predictable `.tmp` Symlink Attacks & Concurrent Collisions (`utils/zeroize.rs`, `vault/store.rs`, `cli/file_cmd.rs`, `cli/kem_cmd.rs`, `cli/sign_cmd.rs`, `archive/pack.rs`)**: Replaced fixed `.tmp`/`.wilis.tmp` filenames with `create_unique_temp_file` and `write_atomic_file` using CSPRNG 16-hex suffixes + `OpenOptions::create_new(true)` (`O_CREAT | O_EXCL` on Unix, `CREATE_NEW` on Windows) so temp files never follow pre-existing symlinks and never collide across concurrent invocations; added `sync_all()` crash durability before `fs::rename`, enforced Unix `0600` permissions on decrypted outputs (`decrypt-file`, `pub-decrypt`) from birth, and refused writing sensitive files onto existing symlinks.
- **Hard-Link Detection for In-Place Safety (`utils/zeroize.rs`)**: Extended `paths_refer_to_same_file` on Unix to compare `(dev, ino)` metadata so hard links pointing to the same file are also caught as `--in == --out`.
- **Audit Edge-Case & Benchmark Fixes (`audit/key_sensitivity.rs`, `audit/randomness.rs`, `cli/bench_cmd.rs`)**: Fixed `analyze_kem_cca2(0)` vacuously reporting `passed: true`; guarded `runs_denom <= 0.0` against `0.0 / 0.0 = NaN` in `analyze_keystream_randomness`; replaced `assert_eq!` panic in `wilis bench` with full plaintext equality check returning `Err` plus `elapsed.max(1e-9)` div-by-zero guard.
- **Accurate OS I/O Error Propagation (`cli/file_cmd.rs`, `format/header.rs`, `archive/unpack.rs`)**: Distinguished `io::ErrorKind::UnexpectedEof` (truncated format) from real OS errors (such as `EISDIR` when passing a directory path) so filesystem errors are never disguised as truncation errors.
- **Error-Path Hex & CLI Memory Zeroization (`utils/hex.rs`, `cli/mod.rs`)**: Zeroized partially decoded secret bytes on `decode_hex` failure and wiped CLI `plaintext`, `secret_hex`, and `shares` buffers immediately after command execution.
- **Regression Suite (`tests/known_answer_vectors.rs`)**: Added `regression_v044_audit_fixes_verified` (**39 / 39 tests**).

## [0.4.3] - 2026-11-23

### Bug Fixes, Python FFI Hardening & Locked Known-Answer Test Vectors (Round 3)
- **WOTS+ Step Overflow Guard (`sign/wots.rs`)**: Prevented silent `u8` addition wrap-around in `wots_chain` by computing bounds in `u16` and asserting `start_step + steps <= WOTS_MAX_STEP` (`15`).
- **Python Binding Hardening (`bindings/python/wilis_py.py`)**: Added strict `0..=0xFFFF_FFFF` `u32` bounds checks in `kdf_derive` (preventing silent `ctypes.c_uint32` wrap-around that could weaken KDF work factors on out-of-range ints), added `try ... finally: ctypes.memset(...)` zeroization for all temporary ctypes secret buffers (`key`, `passphrase`, `sk`, `pt`, `ss`), added constant-time `mac_verify` (`hmac.compare_digest`), and expanded `__main__` self-tests.
- **Panic-Free `ContainerHeader::to_bytes` (`format/header.rs`)**: Replaced `.expect(...)` when `version == FORMAT_VERSION_V2` and `chunk_size == None` with safe `DEFAULT_CHUNK_SIZE` fallback.
- **RAII Secret Zeroization & Buffer Wiping (`cli/args.rs`, `cli/split_cmd.rs`, `utils/base64.rs`, `aead/absorb.rs`)**: Replaced manual passphrase/vault-value cleanup with an RAII `ZeroizeStr` wrapper so even `?` early returns wipe parsed CLI secrets; zeroized Base64 decode scratch & partial output buffers on error, `split-key`/`combine-key` formatted secret strings, and `absorb_aad` padded block.
- **Locked Known-Answer Test Vectors (`tests/known_answer_vectors.rs`)**: Verified all 32 `ROUND_CONSTANTS` mathematically match `floor(2^64 * frac(p_i^(1/5)))` (32/32 exact) and locked permanent golden KAT vectors for `WilisPerm-384`, `WilisHash-256`, `WilisXOF`, `WilisMAC`/`derive_subkey`, `WilisAEAD`, `WilisKDF` v2 (with & without 2FA keyfile), `WilisKEM`, `WilisSign`, and `WilisRatchet` (**38 / 38 tests**).

## [0.4.2] - 2026-11-23

### Bug Fixes & Deep Audit Pass (Round 2)
- **Constant-Time Post-Quantum KEM Arithmetic (`kem/poly.rs`, `kem/mlwe.rs`)**: Eliminated variable-time hardware integer division (`rem_euclid`, `%`) and secret-dependent branches across `Poly::add`, `Poly::sub`, `Poly::mul` (replaced with exact branchless Barrett reduction mod `q = 7681`), `Poly::to_msg_bits`, and `Poly::sample_cbd2`; zeroized `Poly::mul` stack accumulator, `vec_dot` intermediates, partial secret polynomials on `KemSecretKey::from_bytes` errors, and stack RNG seeds on failure; wrapped FO implicit-rejection select mask in `core::hint::black_box`.
- **C-FFI Panic Safety, UB & Buffer Aliasing Protection (`ffi/c_api.rs`)**: Wrapped all 10 `extern "C"` exports in `std::panic::catch_unwind` (preventing panics from unwinding across the C-ABI boundary); rejected lengths `> isize::MAX` before `slice::from_raw_parts(_mut)`; ended input slice borrows before writing outputs so in-place AEAD/hash/MAC/XOF calls are alias-safe; rejected overlapping output buffers in `wilis_kem_keygen`, `wilis_kem_encapsulate`, and `wilis_aead_seal`.
- **Archive Symlink-Escape, Cross-Platform Path & 32-Bit Loop Fixes (`archive/unpack.rs`, `archive/pack.rs`)**: Blocked writing through pre-existing symlinks in extraction directories (`symlink_metadata` check across every path prefix & target); blocked colons/ADS, control chars, trailing dots/spaces, Windows reserved device names (`CON`/`NUL`/`COM1`–`9`/`LPT1`–`9`), and duplicate entry paths; fixed 32-bit `remaining as usize` truncation infinite loop in both `pack_directory` and `unpack_directory`; zeroized `unpack_directory`'s 64 KiB plaintext copy buffer even on error.
- **32-Bit / 64-Bit Cross-Platform KDF Determinism (`kdf/memory_kdf.rs`, `kdf/params.rs`)**: Computed Pass 0 and Pass `1..T` scratchpad index modulo in `u64` before casting to `usize` so `WilisKDF` produces identical keys on both 32-bit and 64-bit targets (100% bit-identical to existing 64-bit keys); used `saturating_mul` in `KdfParams::memory_bytes`.
- **Unix `EINTR` Resilience & Error-Path Zeroization (`stream/`, `utils/prompt.rs`, `utils/random.rs`, `cli/keygen_cmd.rs`, `cli/mac_cmd.rs`)**: Added `ErrorKind::Interrupted` retry loops across streaming/file readers; guaranteed buffer zeroization on error in `encrypt_stream_core`, `hash_keyfile`, `read_hidden_passphrase`, `prompt_once`, `fill_random`, and `generate_key`; enforced `MIN_CHUNK_SIZE` and overflow-checked byte counters in streaming decrypt/encrypt.
- **CLI Parser Hardening (`cli/args.rs`, `cli/vault_cmd.rs`)**: Rejected extra unexpected args on `keygen`/`bench`/`audit`/`hash`, rejected combining `--pass` with `--pass-prompt`, rejected empty `--pass ""`, rejected unused `--name`/`--value` flags on `vault` subcommands, added `--` end-of-options support for text/hash/MAC commands, and added `Drop` zeroization for `VaultAction` secrets plus error-path passphrase wiping.
- **WilisSign, WilisSplit & Sponge Hardening (`sign/`, `split/shamir.rs`, `xof/`, `mac/`, `aead/encrypt.rs`, `ratchet/`)**: Validated `leaf_index < 2^height` during `Signature::from_bytes`, guarded `VerifyingKey::verify` against shift overflow on manually constructed invalid heights, zeroized temporary secret buffers across `SigningKey`, `Share::encode_string`/`decode_string`, `split_secret` error path, `WilisXof::finish_absorb`, `derive_subkey`, and `aead::encrypt_blocks`.
- **Spec, Security Policy & CI Hardening (`SPECIFICATION.md`, `SECURITY.md`, `.github/workflows/`)**: Synced domain separator table (`DOMAIN_XOF`, `DOMAIN_MAC`, `DOMAIN_RATCHET`) and threat model; enforced `RUSTFLAGS="-D warnings"`, `python3 -B`, and live C99 `cc -std=c99 -Wall -Wextra -Werror` header verification in CI; included `CHANGELOG.md` in CI release bundles.

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
