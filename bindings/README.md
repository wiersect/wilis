# Wilis Language Bindings (v0.7.0 — 16 Languages, Zero External Dependencies)

Every binding in this directory wraps the **libwilis C99 ABI (`include/wilis.h`, 33 exported functions)** using **only the language's built-in standard library / native FFI** — zero third-party packages, zero npm/pip/NuGet/Maven/pub dependencies.

## Build the Native Shared Library First

```bash
cargo build --release
```

This produces:
- **Linux:** `target/release/libwilis.so` (+ static `libwilis.a`)
- **macOS:** `target/release/libwilis.dylib` (+ static `libwilis.a`)
- **Windows:** `target/release/wilis.dll` (+ `wilis.dll.lib`)

You can override library discovery in dynamic-FFI bindings via the `WILIS_LIB` environment variable.

## Complete 16-Language Matrix

| # | Language / Runtime | Entry Point | Mechanism | C-ABI Coverage | External Deps |
|---|---|---|---|---|---|
| 1 | **C99** | [`include/wilis.h`](../include/wilis.h) | Native C99 header | 33 / 33 | 0 |
| 2 | **C++17** | [`include/wilis.hpp`](../include/wilis.hpp) | Header-only RAII (`SecretArray<N>`) | 33 / 33 | 0 |
| 3 | **Python 3** | [`bindings/python/wilis_py.py`](python/wilis_py.py) | stdlib `ctypes` | 33 / 33 | 0 |
| 4 | **Go** | [`bindings/go/wilis.go`](go/wilis.go) | Native `cgo` | 33 / 33 | 0 |
| 5 | **Node.js / TypeScript** | [`bindings/node/wilis.mjs`](node/wilis.mjs) & [`wilis_napi.c`](node/wilis_napi.c) | Zero-dep ESM SDK + native N-API C addon | CLI + Native N-API | 0 |
| 6 | **Deno** | [`bindings/deno/wilis.ts`](deno/wilis.ts) | Built-in `Deno.dlopen` FFI | 33 / 33 | 0 |
| 7 | **Bun** | [`bindings/bun/wilis.ts`](bun/wilis.ts) | Built-in `bun:ffi` | 33 / 33 | 0 |
| 8 | **C# / .NET 8+** | [`bindings/csharp/Wilis.cs`](csharp/Wilis.cs) | Built-in P/Invoke (`DllImport`) | 33 / 33 | 0 |
| 9 | **Java 22+** | [`bindings/java/Wilis.java`](java/Wilis.java) | Built-in Project Panama FFM (`java.lang.foreign`) | 33 / 33 | 0 |
| 10 | **Kotlin JVM** | [`bindings/kotlin/Wilis.kt`](kotlin/Wilis.kt) | Idiomatic Kotlin wrapper over Panama FFM | 33 / 33 | 0 |
| 11 | **Zig 0.13+** | [`bindings/zig/wilis.zig`](zig/wilis.zig) | Native `extern "c"` | 33 / 33 | 0 |
| 12 | **Swift** | [`bindings/swift/Wilis.swift`](swift/Wilis.swift) | Native `module.modulemap` C-interop | 33 / 33 | 0 |
| 13 | **Ruby 3+** | [`bindings/ruby/wilis.rb`](ruby/wilis.rb) | stdlib `Fiddle` | 33 / 33 | 0 |
| 14 | **PHP 8+** | [`bindings/php/Wilis.php`](php/Wilis.php) | Built-in `FFI` extension | 33 / 33 | 0 |
| 15 | **LuaJIT** | [`bindings/lua/wilis.lua`](lua/wilis.lua) | Built-in `ffi.cdef` | 33 / 33 | 0 |
| 16 | **Dart 3+** | [`bindings/dart/wilis.dart`](dart/wilis.dart) | Built-in `dart:ffi` | 33 / 33 | 0 |

## All 33 Exported C-ABI Functions

- **Metadata & Safety (4):** `wilis_version`, `wilis_ct_eq`, `wilis_zeroize`, `wilis_random_bytes`
- **Hashing, MAC & Derivation (5):** `wilis_hash_256`, `wilis_tree_hash_256`, `wilis_mac_256`, `wilis_subkey_derive`, `wilis_xof_derive`
- **Authenticated Encryption (4):** `wilis_aead_seal`, `wilis_aead_open`, `wilis_siv_seal`, `wilis_siv_open`
- **Memory-Hard KDF (2):** `wilis_kdf_derive` (v2 sequential), `wilis_kdf_parallel_derive` (v3 multi-lane)
- **Post-Quantum KEM (3):** `wilis_kem_keygen`, `wilis_kem_encapsulate`, `wilis_kem_decapsulate`
- **Post-Quantum Signatures (6):** `wilis_sign_keygen`, `wilis_sign_message`, `wilis_verify_message`, `wilis_slh_keygen`, `wilis_slh_sign`, `wilis_slh_verify`
- **Post-Quantum Signcryption (2):** `wilis_signcrypt`, `wilis_unsigncrypt` (WPSC v1)
- **Protocols & Utilities (7):** `wilis_totp_at`, `wilis_fpe_encrypt`, `wilis_fpe_decrypt`, `wilis_mnemonic_encode`, `wilis_mnemonic_decode`, `wilis_lz_compress`, `wilis_lz_decompress`

## Quick Self-Test Commands

```bash
# Python 3
python3 -B bindings/python/wilis_py.py

# Go
cd bindings/go && LD_LIBRARY_PATH=../../target/release go test -v ./...

# Node.js
node bindings/node/test.mjs

# Ruby
ruby bindings/ruby/wilis.rb

# PHP 8+
php -d ffi.enable=true bindings/php/Wilis.php

# Java 22+
javac --release 22 bindings/java/Wilis.java
java --enable-native-access=ALL-UNNAMED -cp bindings/java Wilis

# Deno / Bun / Zig / LuaJIT / Dart
deno run --allow-ffi --allow-env --allow-read bindings/deno/wilis.ts
bun run bindings/bun/wilis.ts
zig test bindings/zig/wilis.zig -Ltarget/release -lwilis -rpath target/release
luajit bindings/lua/wilis.lua
dart run bindings/dart/wilis.dart
```

## Security Notes

- Every C-ABI entry point validates pointers, guards against Rust panics unwinding across FFI (`catch_unwind`), rejects `len > isize::MAX`, and wipes output buffers on authentication failure (`WILIS_ERR_AUTH_FAILED = -2`).
- Variable-length output calls (`signcrypt`, `unsigncrypt`, `fpe_*`, `mnemonic_*`, `lz_*`) follow a strict two-call sizing protocol: pass `(NULL, 0, &needed)` to receive `WILIS_ERR_BUF_TOO_SMALL (-4)` with the exact byte length in `needed`, then allocate and call again.
- Use `wilis_zeroize` (or C++ `wilis::SecretArray<N>` / C# `WilisSecret`) to clear raw key buffers after use.
