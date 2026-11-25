<div align="center">

# WILIS

### Standalone Post-Quantum & Symmetric Cryptography Suite in Pure Rust

[![CI](https://github.com/wiersect/wilis/actions/workflows/ci.yml/badge.svg)](https://github.com/wiersect/wilis/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/wiersect/wilis?color=7c3aed)](https://github.com/wiersect/wilis/releases)
[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-0%20External%20Crates-brightgreen.svg)](Cargo.toml)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*One original 384-bit permutation. Zero external crypto libraries. NTT-accelerated Module-LWE KEM (`WPKE` v2), stateless (`WilisSLH`) & streaming stateful (`WilisSign`) PQ signatures, PQ Signcryption, PQ-PCS Ratchet & TCP P2P transport (`WilisNet`), AEAD & Nonce-Misuse-Resistant SIV, AVX2/NEON SIMD, parallel Merkle TreeHash & multi-lane KDF, TOTP/FPE/VSS/ZKP/TimeLock/PAKE, seekable & streaming v2 containers, plausible-deniability hidden volumes, BMP/WAV steganography, OS `mlock`/`shred`, C/Python/Go/Node bindings, and an 8-part scientific cryptanalysis + timing audit.*

[Architecture](#architecture) · [Specification](SPECIFICATION.md) · [Audit Results](#verified-cryptanalysis--benchmarks) · [CLI Quickstart](#cli-quickstart) · [Bindings (C / Python / Go / Node)](#bindings) · [Security](SECURITY.md)

</div>

---

## Overview

**Wilis** is a self-contained cryptographic engineering suite written 100% in pure Rust (`std` only, **zero external dependencies**). Every primitive derives strictly from a single original **384-bit bijective permutation (`WilisPerm-384`)**:

| Module | Primitives | Key Security & Engineering Guarantees |
| :--- | :--- | :--- |
| **`core/`** | **`WilisPerm-384` + SIMD** | Hybrid ARX + bitsliced `Chi-5`/`Feistel-6` + 3-tap diffusion; runtime **AVX2 4-way** & **NEON 2-way** SIMD |
| **`aead/`** | **`WilisAEAD` & `WilisAEAD-SIV`** | 256-bit key, 192-bit nonce, 256-bit tag, key-commitment + deterministic **Nonce-Misuse-Resistant SIV** (64B tag) |
| **`kem/`** | **`WilisKEM`, `WPKE` v2, `WPSC`** | **NTT-accelerated (`O(N log N)` mod 7681)** Module-LWE IND-CCA2 KEM + 64-recipient streaming `WPKE` v2 + PQ **Signcryption** |
| **`sign/`** | **`WilisSign` & `WilisSLH`** | Stateful WOTS+ Merkle (`WSIG` v1/v2 multi-GB streaming) + **Stateless unlimited-use `WilisSLH`** (FORS + Hypertree) |
| **`ratchet/`** | **`WilisRatchet` & `WRST`** | Forward-secret symmetric ratchet + **PQ-PCS Ratchet (`WHSH`/`WRP2`/`WPRK`)** + encrypted persistent state (`WRST` v1) |
| **`net/`** | **`WilisNet` PQ TCP** | Pure-`std::net` PQ encrypted framed TCP P2P transfer (`wilis send`/`recv`) in **PKI** & **zero-PKI PAKE** modes with auto PCS rekey |
| **`protocols/`** | **6 Advanced Protocols** | **`WilisTOTP`** (Base32 2FA), **`WilisFPE`** (arbitrary radix), **`WilisVSS`** + Proactive Refresh, **`WilisZKP`**, **`WilisTimeLock`**, **`WilisPAKE`** |
| **`kdf/`** | **`WilisKDF` v2 & v3 Parallel** | 16–64 MiB hybrid memory-hard KDF + 2FA Keyfile + **1..16-lane parallel `WilisKDF` v3** |
| **`hash/` & `xof/` & `mac/`** | **`WilisHash`, `WilisTreeHash`, `WilisXOF`, `WilisMAC`** | Incremental 256-bit sponge hash, **parallel multi-core Merkle TreeHash + `O(log N)` chunk proofs**, XOF, keyed MAC & subkeys |
| **`stream/` & `archive/`** | **`WILS` v2, `WSEK` v1, `WDIR` v2** | Chunked streaming AEAD, **`O(1)` random-access Seekable Container (`WSEK`)**, constant-RAM streaming **`WDIR` v2** (+ empty dirs, exec bit, `WilisLZ`) |
| **`vault/` & `split/`** | **`WilisVault`, `WilisHidden`, `WilisSplit`** | Atomic vault (`rekey`/`search`/`totp`/`export`/`import`), **Plausible Deniability Hidden Volumes**, Shamir `K`-of-`N` over `GF(2^8)` |
| **`utils/`** | **Hardening, Privacy & Formats** | OS `RLIMIT_CORE=0` / `PR_SET_DUMPABLE=0` / `mlock` (`LockedBuf`), **`shred`**, **`WilisLZ`**, **`WilisPad`**, **`WilisArmor`**, **256-word Mnemonic**, **`WENC`/`WKRN` Keyring**, **BMP/WAV Stego** |
| **`audit/`** | **`wilis audit` (8-Part)** | SAC (1–16), BIC, exact DDT/LAT, NIST randomness, related-key, KEM CCA2, PQ protocols, **Welch's t-test (`dudect`) & NTT/SIMD/SIV/SLH** |
| **`ffi/` & `bindings/`** | **`libwilis` C99 / Py / Go / Node** | Panic-safe C-ABI (`include/wilis.h`) + zero-dep Python 3, Go (cgo), and Node.js/TypeScript wrappers |

---

## Verified Cryptanalysis & Benchmarks

| Verification Check | Measured Result | Target / Ideal | Status |
| :--- | :--- | :--- | :---: |
| **Bijectivity** `P⁻¹(P(x)) == x` | Exact identity across rounds 1, 4, 12, 16 | Exact 1-to-1 bijection | **PASS** |
| **Full Diffusion Round** (SAC 384-bit) | **Round 2** (`191.98/384` = `49.99%`) | ≤ Round 4 (10–14 round margin) | **PASS** |
| **Bit Independence Criterion (BIC)** | Avg `\|corr\| = 0.0348`, Max `0.1641` | Avg `< 0.06`, Max `< 0.25` | **PASS** |
| **`Chi-5` S-Box Exact DDT / LAT** | Bijective, Diff Unif `8`, Nonlinearity `8` | Paired with ARX degree-63 carries | **PASS** |
| **Keystream Randomness** (128 KiB) | Entropy **`7.99853` bits/B**, Monobit `0.50007`, Runs `Z=0.87`, χ² `267.85` | NIST SP 800-22 bounds | **PASS** |
| **Related-Key Sensitivity** (256 flips) | **`50.07%`** ciphertext · **`49.89%`** tag diffusion | `[47.5% .. 52.5%]` | **PASS** |
| **`WilisKEM` IND-CCA2 + NTT** | Zero decapsulation errors, FO implicit rejection, bit-exact NTT == schoolbook | Exact match & tamper reject | **PASS** |
| **Empirical Constant-Time (`dudect`)** | Welch's t-test on `ct_eq` + bit-exact AVX2/NEON SIMD + SIV + SLH | `\|t\| < 12.0` & exact vectors | **PASS** |
| **Adversarial Parser Fuzz & Miri UB** | 330+ malformed/truncated/overflow payloads across **all 39 parsers** + nightly Miri | **Zero panics, zero UB** | **PASS** |
| **Cross-Platform CI & Test Suite** | **`60 / 60` tests passing** (Linux, macOS, Windows + Miri + KAT) | `-D warnings`, 0 external crates | **PASS** |

---

## Build & Verify

```bash
git clone https://github.com/wiersect/wilis.git
cd wilis

# Run all 60 tests (locked KAT vectors, NTT, SIMD, SIV, TreeHash, SLH, TCP P2P, protocols, FFI & 39-parser fuzz)
cargo test

# Build optimized CLI binary + native shared library (libwilis.so / .dylib / .dll)
cargo build --release

# Run 8-part scientific cryptanalysis + timing audit, NTT/SIMD benchmark, and Python C-FFI test
./target/release/wilis audit
./target/release/wilis bench
python3 bindings/python/wilis_py.py
```

---

## CLI Quickstart

```bash
# 1. UNIX stdin/stdout streaming pipes & constant-memory compressed folder archiving
cat secret.txt | ./target/release/wilis encrypt-file --key "$KEY" --in - --out - | ./target/release/wilis decrypt-file --key "$KEY" --in - --out -
./target/release/wilis encrypt-dir --pass-prompt --strength high --compress --in ./secrets --out ./secrets.wils

# 2. Stateless Post-Quantum Digital Signatures (WilisSLH — unlimited signatures, no mutable counter!)
./target/release/wilis slh-keygen --out dev_slh
./target/release/wilis slh-sign   --sk dev_slh.wls --armor --in release.tar.gz --out release.tar.gz.wlsg.asc
./target/release/wilis slh-verify --pk dev_slh.wlp --in release.tar.gz --sig release.tar.gz.wlsg.asc

# 3. Post-Quantum Encrypted P2P File Transfer over TCP (zero-PKI PAKE or full PKI + auto PCS rekey)
./target/release/wilis recv --listen 0.0.0.0:9443 --out-dir ./incoming --pass "one-time-transfer-code"
./target/release/wilis send --addr 127.0.0.1:9443 --in ./archive.wils  --pass "one-time-transfer-code"

# 4. Vault upgrades (rekey, search, 2FA TOTP, armored backup) & Keyring / Mnemonic / Inspect / Shred
./target/release/wilis vault totp   --file vault.wils --pass-prompt --name github_totp
./target/release/wilis vault search --file vault.wils --pass-prompt --query github
./target/release/wilis vault rekey  --file vault.wils --pass-prompt --new-strength paranoid
./target/release/wilis mnemonic encode --key "$KEY"
./target/release/wilis inspect ./secrets.wils
./target/release/wilis passgen --words 6 --count 3
./target/release/wilis shred --file ./plain.tmp --passes 3
./target/release/wilis completions bash
```

---

## Bindings

- **C / C++:** [`include/wilis.h`](include/wilis.h) — C99 strict (`-Wall -Wextra -Werror`) covering Hash, TreeHash, MAC, Subkey, XOF, AEAD, SIV, KDF, KEM, Stateful Sign & Stateless SLH.
- **Python 3:** [`bindings/python/wilis_py.py`](bindings/python/wilis_py.py) — zero-dependency `ctypes` wrapper with automatic buffer zeroization.
- **Go (cgo):** [`bindings/go/wilis.go`](bindings/go/wilis.go) — zero-dependency cgo wrapper over `include/wilis.h` & `libwilis`.
- **Node.js / TypeScript:** [`bindings/node/wilis.mjs`](bindings/node/wilis.mjs) & [`bindings/node/wilis.d.ts`](bindings/node/wilis.d.ts) — zero-dependency ESM client using native stdio pipes.

---

## Security Notice

> **Important:** Wilis is a custom, independent cryptographic design created for cryptographic engineering research, education, and experimentation. Like any newly invented cipher or lattice construction, it has not undergone multi-year external public cryptanalysis. Do **not** rely on custom cryptography alone for regulated, financial, or mission-critical production systems — use peer-reviewed standards (AES-GCM, ChaCha20-Poly1305, Argon2id, ML-KEM, ML-DSA, SLH-DSA) for production workloads. See **[`SECURITY.md`](SECURITY.md)**.

## License

Licensed under the **[MIT License](LICENSE)**.
