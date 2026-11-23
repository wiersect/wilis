# Contributing to Wilis

Thank you for your interest in contributing to **Wilis**! Whether you are submitting cryptanalysis, optimizing constant-time Rust implementations, expanding test coverage, or improving documentation, your work is welcome.

---

## Core Engineering Rules

Every pull request **must** respect these non-negotiable project principles:

1. **Zero External Dependencies:** `[dependencies]` in `Cargo.toml` must remain completely empty. All code uses Rust `std` only.
2. **Flat Modular Layout:** Keep every domain in its own root folder (`core/`, `aead/`, `kdf/`, `hash/`, `format/`, `stream/`, `audit/`, `utils/`, `cli/`, `tests/`) with focused single-responsibility files.
3. **Constant-Time & Memory Hygiene:** Never introduce secret-dependent branches or secret-indexed memory lookup tables in cryptographic paths. Wipe sensitive buffers with `utils::zeroize`.
4. **Full English Codebase:** All identifiers, docstrings, comments, CLI text, and documentation must be written in clear English.

---

## Development Workflow

```bash
# 1. Run all unit, security, streaming, and cryptanalysis tests
cargo test

# 2. Build optimized release binary
cargo build --release

# 3. Verify all scientific cryptanalysis checks & benchmarks pass
./target/release/wilis audit
./target/release/wilis bench
```

## Submitting Cryptanalysis

If you discover a differential/linear trail, reduced-round distinguisher, state-recovery attack, or implementation vulnerability, please open an issue using the **Cryptanalysis Report** template or review [`SECURITY.md`](SECURITY.md).
