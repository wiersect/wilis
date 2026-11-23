"""
Zero-dependency Python 3 binding for the Wilis Cryptography Suite (`libwilis`).

Build the shared library first with:
    cargo build --release

Then use:
    from wilis_py import Wilis
    w = Wilis()
    key = w.random_bytes(32)
    nonce = w.random_bytes(24)
    ct, tag = w.aead_seal(key, nonce, b"ctx", b"Hello from Python!")
    pt = w.aead_open(key, nonce, b"ctx", ct, tag)
"""

from __future__ import annotations

import ctypes
import pathlib
import platform
from typing import Optional, Tuple


class WilisAuthError(Exception):
    """Raised when WilisAEAD authentication tag verification fails."""


class WilisError(Exception):
    """Raised when a Wilis FFI call fails due to invalid arguments or OS error."""


def _default_library_path() -> pathlib.Path:
    root = pathlib.Path(__file__).resolve().parents[2]
    sys_name = platform.system()
    if sys_name == "Windows":
        lib_name = "wilis.dll"
    elif sys_name == "Darwin":
        lib_name = "libwilis.dylib"
    else:
        lib_name = "libwilis.so"

    for profile in ("release", "debug"):
        candidate = root / "target" / profile / lib_name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"Could not find {lib_name} in {root / 'target'}. Run `cargo build --release` first."
    )


class Wilis:
    """High-level Python interface over the native `libwilis` C-ABI."""

    def __init__(self, library_path: Optional[str | pathlib.Path] = None) -> None:
        path = pathlib.Path(library_path) if library_path else _default_library_path()
        self._lib = ctypes.CDLL(str(path))
        self._bind_signatures()

    def _bind_signatures(self) -> None:
        c_u8_p = ctypes.POINTER(ctypes.c_uint8)

        self._lib.wilis_hash_256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, c_u8_p]
        self._lib.wilis_hash_256.restype = ctypes.c_int32

        self._lib.wilis_aead_seal.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            c_u8_p,
            c_u8_p,
        ]
        self._lib.wilis_aead_seal.restype = ctypes.c_int32

        self._lib.wilis_aead_open.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            c_u8_p,
        ]
        self._lib.wilis_aead_open.restype = ctypes.c_int32

        self._lib.wilis_kdf_derive.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            c_u8_p,
        ]
        self._lib.wilis_kdf_derive.restype = ctypes.c_int32

        self._lib.wilis_random_bytes.argtypes = [c_u8_p, ctypes.c_size_t]
        self._lib.wilis_random_bytes.restype = ctypes.c_int32

    def hash_256(self, data: bytes) -> bytes:
        out = (ctypes.c_uint8 * 32)()
        rc = self._lib.wilis_hash_256(data, len(data), out)
        if rc != 0:
            raise WilisError(f"wilis_hash_256 failed (rc={rc})")
        return bytes(out)

    def random_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""
        out = (ctypes.c_uint8 * length)()
        rc = self._lib.wilis_random_bytes(out, length)
        if rc != 0:
            raise WilisError(f"wilis_random_bytes failed (rc={rc})")
        return bytes(out)

    def kdf_derive(
        self,
        passphrase: bytes,
        salt: bytes,
        memory_blocks: int = 349_520,
        passes: int = 3,
    ) -> bytes:
        if len(salt) != 24:
            raise ValueError("salt must be exactly 24 bytes")
        out = (ctypes.c_uint8 * 32)()
        rc = self._lib.wilis_kdf_derive(
            passphrase, len(passphrase), salt, memory_blocks, passes, out
        )
        if rc != 0:
            raise WilisError(f"wilis_kdf_derive failed (rc={rc})")
        return bytes(out)

    def aead_seal(
        self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
    ) -> Tuple[bytes, bytes]:
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        if len(nonce) != 24:
            raise ValueError("nonce must be exactly 24 bytes")
        ct_buf = (ctypes.c_uint8 * len(plaintext))()
        tag_buf = (ctypes.c_uint8 * 32)()
        rc = self._lib.wilis_aead_seal(
            key, nonce, aad, len(aad), plaintext, len(plaintext), ct_buf, tag_buf
        )
        if rc != 0:
            raise WilisError(f"wilis_aead_seal failed (rc={rc})")
        return bytes(ct_buf), bytes(tag_buf)

    def aead_open(
        self, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes
    ) -> bytes:
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        if len(nonce) != 24:
            raise ValueError("nonce must be exactly 24 bytes")
        if len(tag) != 32:
            raise ValueError("tag must be exactly 32 bytes")
        pt_buf = (ctypes.c_uint8 * len(ciphertext))()
        rc = self._lib.wilis_aead_open(
            key, nonce, aad, len(aad), ciphertext, len(ciphertext), tag, pt_buf
        )
        if rc == -2:
            raise WilisAuthError("authentication failed")
        if rc != 0:
            raise WilisError(f"wilis_aead_open failed (rc={rc})")
        return bytes(pt_buf)


if __name__ == "__main__":
    w = Wilis()
    key = w.random_bytes(32)
    nonce = w.random_bytes(24)
    msg = b"Hello from Wilis Python C-FFI binding!"
    ct, tag = w.aead_seal(key, nonce, b"py-aad", msg)
    pt = w.aead_open(key, nonce, b"py-aad", ct, tag)
    assert pt == msg
    print("Python C-FFI self-test: PASS")
    print("WilisHash-256('Wilis'):", w.hash_256(b"Wilis").hex())
