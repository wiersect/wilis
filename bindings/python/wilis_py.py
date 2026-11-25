"""
Zero-dependency Python 3 binding for the Wilis v0.5.0 Cryptography Suite (`libwilis`).

Build the shared library first with:
    cargo build --release
"""

from __future__ import annotations

import ctypes
import hmac
import pathlib
import platform
from typing import Optional, Tuple

KEM_PK_BYTES = 1284
KEM_SK_BYTES = 2600
KEM_CT_BYTES = 1668
KEM_SS_BYTES = 32
SIGN_PK_BYTES = 101
SIGN_SK_BYTES = 137
SIGN_MAX_SIG_BYTES = 2506
_U32_MAX = 0xFFFF_FFFF


class WilisAuthError(Exception):
    """Raised when WilisAEAD authentication tag verification fails."""


class WilisError(Exception):
    """Raised when a Wilis FFI call fails due to invalid arguments or OS error."""


def _wipe_buf(buf: Optional[ctypes.Array]) -> None:
    if buf is not None and ctypes.sizeof(buf) > 0:
        ctypes.memset(ctypes.addressof(buf), 0, ctypes.sizeof(buf))


def _check_u32(val: int, name: str) -> None:
    if isinstance(val, bool) or not isinstance(val, int) or val < 0 or val > _U32_MAX:
        raise ValueError(f"{name} must be an integer in 0..={_U32_MAX}")


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
        c_vp = ctypes.c_void_p
        c_sz = ctypes.c_size_t

        self._lib.wilis_hash_256.argtypes = [c_vp, c_sz, c_u8_p]
        self._lib.wilis_hash_256.restype = ctypes.c_int32

        self._lib.wilis_mac_256.argtypes = [c_vp, c_vp, c_sz, c_u8_p]
        self._lib.wilis_mac_256.restype = ctypes.c_int32

        self._lib.wilis_xof_derive.argtypes = [c_vp, c_sz, c_vp, c_sz, c_u8_p, c_sz]
        self._lib.wilis_xof_derive.restype = ctypes.c_int32

        self._lib.wilis_aead_seal.argtypes = [c_vp, c_vp, c_vp, c_sz, c_vp, c_sz, c_u8_p, c_u8_p]
        self._lib.wilis_aead_seal.restype = ctypes.c_int32

        self._lib.wilis_aead_open.argtypes = [c_vp, c_vp, c_vp, c_sz, c_vp, c_sz, c_vp, c_u8_p]
        self._lib.wilis_aead_open.restype = ctypes.c_int32

        self._lib.wilis_kdf_derive.argtypes = [c_vp, c_sz, c_vp, ctypes.c_uint32, ctypes.c_uint32, c_u8_p]
        self._lib.wilis_kdf_derive.restype = ctypes.c_int32

        self._lib.wilis_kem_keygen.argtypes = [c_u8_p, c_u8_p]
        self._lib.wilis_kem_keygen.restype = ctypes.c_int32

        self._lib.wilis_kem_encapsulate.argtypes = [c_vp, c_u8_p, c_u8_p]
        self._lib.wilis_kem_encapsulate.restype = ctypes.c_int32

        self._lib.wilis_kem_decapsulate.argtypes = [c_vp, c_vp, c_u8_p]
        self._lib.wilis_kem_decapsulate.restype = ctypes.c_int32

        self._lib.wilis_random_bytes.argtypes = [c_u8_p, c_sz]
        self._lib.wilis_random_bytes.restype = ctypes.c_int32

        self._lib.wilis_version.argtypes = []
        self._lib.wilis_version.restype = ctypes.c_char_p

        self._lib.wilis_subkey_derive.argtypes = [c_vp, c_vp, c_sz, c_u8_p]
        self._lib.wilis_subkey_derive.restype = ctypes.c_int32

        self._lib.wilis_sign_keygen.argtypes = [ctypes.c_uint8, c_u8_p, c_u8_p]
        self._lib.wilis_sign_keygen.restype = ctypes.c_int32

        self._lib.wilis_sign_message.argtypes = [
            c_u8_p, c_vp, c_sz, c_u8_p, c_sz, ctypes.POINTER(c_sz)
        ]
        self._lib.wilis_sign_message.restype = ctypes.c_int32

        self._lib.wilis_verify_message.argtypes = [c_vp, c_vp, c_sz, c_vp, c_sz]
        self._lib.wilis_verify_message.restype = ctypes.c_int32

    def version(self) -> str:
        raw = self._lib.wilis_version()
        return raw.decode("utf-8") if raw else ""

    def hash_256(self, data: bytes) -> bytes:
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None
        ptr = ctypes.cast(buf, ctypes.c_void_p) if buf is not None else ctypes.c_void_p(0)
        out = (ctypes.c_uint8 * 32)()
        try:
            rc = self._lib.wilis_hash_256(ptr, len(data), out)
            if rc != 0:
                raise WilisError(f"wilis_hash_256 failed (rc={rc})")
            return bytes(out)
        finally:
            _wipe_buf(buf)

    def mac_256(self, key: bytes, message: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        k_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key)
        m_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message) if message else None
        m_ptr = ctypes.cast(m_buf, ctypes.c_void_p) if m_buf is not None else ctypes.c_void_p(0)
        out = (ctypes.c_uint8 * 32)()
        try:
            rc = self._lib.wilis_mac_256(ctypes.cast(k_buf, ctypes.c_void_p), m_ptr, len(message), out)
            if rc != 0:
                raise WilisError(f"wilis_mac_256 failed (rc={rc})")
            return bytes(out)
        finally:
            _wipe_buf(k_buf)
            _wipe_buf(m_buf)

    def mac_verify(self, key: bytes, message: bytes, expected_tag: bytes) -> bool:
        """Verifies a 256-bit WilisMAC tag in constant time."""
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        if len(expected_tag) != 32:
            return False
        actual = self.mac_256(key, message)
        return hmac.compare_digest(actual, expected_tag)

    def xof_derive(self, label: bytes, seed: bytes, out_len: int) -> bytes:
        if isinstance(out_len, bool) or not isinstance(out_len, int) or out_len < 0:
            raise ValueError("out_len must be a non-negative integer")
        if out_len == 0:
            return b""
        l_buf = (ctypes.c_uint8 * len(label)).from_buffer_copy(label) if label else None
        s_buf = (ctypes.c_uint8 * len(seed)).from_buffer_copy(seed) if seed else None
        l_ptr = ctypes.cast(l_buf, ctypes.c_void_p) if l_buf is not None else ctypes.c_void_p(0)
        s_ptr = ctypes.cast(s_buf, ctypes.c_void_p) if s_buf is not None else ctypes.c_void_p(0)
        out = (ctypes.c_uint8 * out_len)()
        try:
            rc = self._lib.wilis_xof_derive(l_ptr, len(label), s_ptr, len(seed), out, out_len)
            if rc != 0:
                raise WilisError(f"wilis_xof_derive failed (rc={rc})")
            return bytes(out)
        finally:
            _wipe_buf(s_buf)
            _wipe_buf(out)

    def random_bytes(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("length must be a non-negative integer")
        if length == 0:
            return b""
        out = (ctypes.c_uint8 * length)()
        try:
            rc = self._lib.wilis_random_bytes(out, length)
            if rc != 0:
                raise WilisError(f"wilis_random_bytes failed (rc={rc})")
            return bytes(out)
        finally:
            _wipe_buf(out)

    def kdf_derive(
        self,
        passphrase: bytes,
        salt: bytes,
        memory_blocks: int = 349_520,
        passes: int = 3,
    ) -> bytes:
        if len(salt) != 24:
            raise ValueError("salt must be exactly 24 bytes")
        _check_u32(memory_blocks, "memory_blocks")
        _check_u32(passes, "passes")
        p_buf = (ctypes.c_uint8 * len(passphrase)).from_buffer_copy(passphrase) if passphrase else None
        p_ptr = ctypes.cast(p_buf, ctypes.c_void_p) if p_buf is not None else ctypes.c_void_p(0)
        s_buf = (ctypes.c_uint8 * 24).from_buffer_copy(salt)
        out = (ctypes.c_uint8 * 32)()
        try:
            rc = self._lib.wilis_kdf_derive(
                p_ptr, len(passphrase), ctypes.cast(s_buf, ctypes.c_void_p), memory_blocks, passes, out
            )
            if rc != 0:
                raise WilisError(f"wilis_kdf_derive failed (rc={rc})")
            return bytes(out)
        finally:
            _wipe_buf(p_buf)
            _wipe_buf(out)

    def aead_seal(
        self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
    ) -> Tuple[bytes, bytes]:
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        if len(nonce) != 24:
            raise ValueError("nonce must be exactly 24 bytes")
        k_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key)
        n_buf = (ctypes.c_uint8 * 24).from_buffer_copy(nonce)
        a_buf = (ctypes.c_uint8 * len(aad)).from_buffer_copy(aad) if aad else None
        p_buf = (ctypes.c_uint8 * len(plaintext)).from_buffer_copy(plaintext) if plaintext else None
        a_ptr = ctypes.cast(a_buf, ctypes.c_void_p) if a_buf is not None else ctypes.c_void_p(0)
        p_ptr = ctypes.cast(p_buf, ctypes.c_void_p) if p_buf is not None else ctypes.c_void_p(0)
        ct_buf = (ctypes.c_uint8 * len(plaintext))()
        tag_buf = (ctypes.c_uint8 * 32)()
        try:
            rc = self._lib.wilis_aead_seal(
                ctypes.cast(k_buf, ctypes.c_void_p),
                ctypes.cast(n_buf, ctypes.c_void_p),
                a_ptr,
                len(aad),
                p_ptr,
                len(plaintext),
                ct_buf,
                tag_buf,
            )
            if rc != 0:
                raise WilisError(f"wilis_aead_seal failed (rc={rc})")
            return bytes(ct_buf), bytes(tag_buf)
        finally:
            _wipe_buf(k_buf)
            _wipe_buf(p_buf)

    def aead_open(
        self, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes
    ) -> bytes:
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        if len(nonce) != 24:
            raise ValueError("nonce must be exactly 24 bytes")
        if len(tag) != 32:
            raise ValueError("tag must be exactly 32 bytes")
        k_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key)
        n_buf = (ctypes.c_uint8 * 24).from_buffer_copy(nonce)
        t_buf = (ctypes.c_uint8 * 32).from_buffer_copy(tag)
        a_buf = (ctypes.c_uint8 * len(aad)).from_buffer_copy(aad) if aad else None
        c_buf = (ctypes.c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext) if ciphertext else None
        a_ptr = ctypes.cast(a_buf, ctypes.c_void_p) if a_buf is not None else ctypes.c_void_p(0)
        c_ptr = ctypes.cast(c_buf, ctypes.c_void_p) if c_buf is not None else ctypes.c_void_p(0)
        pt_buf = (ctypes.c_uint8 * len(ciphertext))()
        try:
            rc = self._lib.wilis_aead_open(
                ctypes.cast(k_buf, ctypes.c_void_p),
                ctypes.cast(n_buf, ctypes.c_void_p),
                a_ptr,
                len(aad),
                c_ptr,
                len(ciphertext),
                ctypes.cast(t_buf, ctypes.c_void_p),
                pt_buf,
            )
            if rc == -2:
                raise WilisAuthError("authentication failed")
            if rc != 0:
                raise WilisError(f"wilis_aead_open failed (rc={rc})")
            return bytes(pt_buf)
        finally:
            _wipe_buf(k_buf)
            _wipe_buf(pt_buf)

    def kem_keygen(self) -> Tuple[bytes, bytes]:
        pk_buf = (ctypes.c_uint8 * KEM_PK_BYTES)()
        sk_buf = (ctypes.c_uint8 * KEM_SK_BYTES)()
        try:
            rc = self._lib.wilis_kem_keygen(pk_buf, sk_buf)
            if rc != 0:
                raise WilisError(f"wilis_kem_keygen failed (rc={rc})")
            return bytes(pk_buf), bytes(sk_buf)
        finally:
            _wipe_buf(sk_buf)

    def kem_encapsulate(self, pk: bytes) -> Tuple[bytes, bytes]:
        if len(pk) != KEM_PK_BYTES:
            raise ValueError(f"pk must be {KEM_PK_BYTES} bytes")
        pk_buf = (ctypes.c_uint8 * KEM_PK_BYTES).from_buffer_copy(pk)
        ct_buf = (ctypes.c_uint8 * KEM_CT_BYTES)()
        ss_buf = (ctypes.c_uint8 * KEM_SS_BYTES)()
        try:
            rc = self._lib.wilis_kem_encapsulate(ctypes.cast(pk_buf, ctypes.c_void_p), ct_buf, ss_buf)
            if rc != 0:
                raise WilisError(f"wilis_kem_encapsulate failed (rc={rc})")
            return bytes(ct_buf), bytes(ss_buf)
        finally:
            _wipe_buf(ss_buf)

    def kem_decapsulate(self, sk: bytes, ct: bytes) -> bytes:
        if len(sk) != KEM_SK_BYTES:
            raise ValueError(f"sk must be {KEM_SK_BYTES} bytes")
        if len(ct) != KEM_CT_BYTES:
            raise ValueError(f"ct must be {KEM_CT_BYTES} bytes")
        sk_buf = (ctypes.c_uint8 * KEM_SK_BYTES).from_buffer_copy(sk)
        ct_buf = (ctypes.c_uint8 * KEM_CT_BYTES).from_buffer_copy(ct)
        ss_buf = (ctypes.c_uint8 * KEM_SS_BYTES)()
        try:
            rc = self._lib.wilis_kem_decapsulate(
                ctypes.cast(sk_buf, ctypes.c_void_p), ctypes.cast(ct_buf, ctypes.c_void_p), ss_buf
            )
            if rc != 0:
                raise WilisError(f"wilis_kem_decapsulate failed (rc={rc})")
            return bytes(ss_buf)
        finally:
            _wipe_buf(sk_buf)
            _wipe_buf(ss_buf)

    def derive_subkey(self, master_key: bytes, context: bytes) -> bytes:
        if len(master_key) != 32:
            raise ValueError("master_key must be exactly 32 bytes")
        mk_buf = (ctypes.c_uint8 * 32).from_buffer_copy(master_key)
        ctx_buf = (ctypes.c_uint8 * len(context)).from_buffer_copy(context) if context else None
        ctx_ptr = ctypes.cast(ctx_buf, ctypes.c_void_p) if ctx_buf is not None else ctypes.c_void_p(0)
        out = (ctypes.c_uint8 * 32)()
        try:
            rc = self._lib.wilis_subkey_derive(
                ctypes.cast(mk_buf, ctypes.c_void_p), ctx_ptr, len(context), out
            )
            if rc != 0:
                raise WilisError(f"wilis_subkey_derive failed (rc={rc})")
            return bytes(out)
        finally:
            _wipe_buf(mk_buf)
            _wipe_buf(out)

    def sign_keygen(self, height: int = 6) -> Tuple[bytes, bytes]:
        if isinstance(height, bool) or not isinstance(height, int) or not (2 <= height <= 10):
            raise ValueError("height must be an integer in 2..=10")
        pk_buf = (ctypes.c_uint8 * SIGN_PK_BYTES)()
        sk_buf = (ctypes.c_uint8 * SIGN_SK_BYTES)()
        try:
            rc = self._lib.wilis_sign_keygen(height, pk_buf, sk_buf)
            if rc != 0:
                raise WilisError(f"wilis_sign_keygen failed (rc={rc})")
            return bytes(pk_buf), bytes(sk_buf)
        finally:
            _wipe_buf(sk_buf)

    def sign_message(self, sk: bytes, message: bytes) -> Tuple[bytes, bytes]:
        """Signs `message` with stateful `WSK1`, returning `(updated_sk, signature)`."""
        if len(sk) != SIGN_SK_BYTES:
            raise ValueError(f"sk must be {SIGN_SK_BYTES} bytes")
        sk_buf = (ctypes.c_uint8 * SIGN_SK_BYTES).from_buffer_copy(sk)
        m_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message) if message else None
        m_ptr = ctypes.cast(m_buf, ctypes.c_void_p) if m_buf is not None else ctypes.c_void_p(0)
        sig_buf = (ctypes.c_uint8 * SIGN_MAX_SIG_BYTES)()
        sig_len = ctypes.c_size_t(0)
        try:
            rc = self._lib.wilis_sign_message(
                sk_buf, m_ptr, len(message), sig_buf, SIGN_MAX_SIG_BYTES, ctypes.byref(sig_len)
            )
            if rc != 0:
                raise WilisError(f"wilis_sign_message failed (rc={rc})")
            return bytes(sk_buf), bytes(sig_buf[: sig_len.value])
        finally:
            _wipe_buf(sk_buf)
            _wipe_buf(m_buf)

    def verify_message(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        if len(pk) != SIGN_PK_BYTES:
            raise ValueError(f"pk must be {SIGN_PK_BYTES} bytes")
        pk_buf = (ctypes.c_uint8 * SIGN_PK_BYTES).from_buffer_copy(pk)
        m_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message) if message else None
        m_ptr = ctypes.cast(m_buf, ctypes.c_void_p) if m_buf is not None else ctypes.c_void_p(0)
        s_buf = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature) if signature else None
        s_ptr = ctypes.cast(s_buf, ctypes.c_void_p) if s_buf is not None else ctypes.c_void_p(0)
        rc = self._lib.wilis_verify_message(
            ctypes.cast(pk_buf, ctypes.c_void_p), m_ptr, len(message), s_ptr, len(signature)
        )
        if rc == 0:
            return True
        if rc == -2:
            return False
        raise WilisError(f"wilis_verify_message failed (rc={rc})")


if __name__ == "__main__":
    w = Wilis()
    assert w.version() == "0.5.0", f"unexpected version: {w.version()!r}"
    # 1. AEAD (including empty plaintext/AAD) + MAC + Subkey + XOF + KDF bounds
    key = w.random_bytes(32)
    nonce = w.random_bytes(24)
    msg = b"\x00Hello from Wilis v0.5.0 Python C-FFI!\x00"
    ct, tag = w.aead_seal(key, nonce, b"py-aad", msg)
    assert w.aead_open(key, nonce, b"py-aad", ct, tag) == msg
    e_ct, e_tag = w.aead_seal(key, nonce, b"", b"")
    assert e_ct == b"" and w.aead_open(key, nonce, b"", e_ct, e_tag) == b""
    mtag = w.mac_256(key, msg)
    assert w.mac_verify(key, msg, mtag)
    assert not w.mac_verify(key, msg + b"!", mtag)
    sub1 = w.derive_subkey(key, b"ctx-a")
    sub2 = w.derive_subkey(key, b"ctx-b")
    assert len(sub1) == 32 and sub1 != sub2
    assert len(w.xof_derive(b"", key, 96)) == 96
    assert len(w.kdf_derive(b"pw", nonce, memory_blocks=64, passes=2)) == 32
    for bad_blocks in (-1, 1 << 32):
        try:
            w.kdf_derive(b"pw", nonce, memory_blocks=bad_blocks, passes=2)
            raise AssertionError("expected ValueError for out-of-range u32")
        except ValueError:
            pass

    # 2. Post-Quantum WilisKEM (including corrupted secret-key LWE rejection)
    pk, sk = w.kem_keygen()
    kem_ct, ss1 = w.kem_encapsulate(pk)
    ss2 = w.kem_decapsulate(sk, kem_ct)
    assert ss1 == ss2
    bad_sk = bytearray(sk)
    bad_sk[10] ^= 0x01
    try:
        w.kem_decapsulate(bytes(bad_sk), kem_ct)
        raise AssertionError("expected WilisError for corrupted KEM secret key")
    except WilisError:
        pass

    # 3. Post-Quantum WilisSign (WOTS+ Merkle)
    spk, ssk = w.sign_keygen(height=2)
    ssk2, sig = w.sign_message(ssk, msg)
    assert ssk2 != ssk
    assert w.verify_message(spk, msg, sig)
    assert not w.verify_message(spk, msg + b"!", sig)

    print("Python C-FFI v0.5.0 (AEAD + MAC + Subkey + XOF + KDF + KEM + Sign): PASS")
