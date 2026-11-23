//! Volatile memory wiping utilities and auto-zeroizing secret key wrapper.

use std::fmt;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

use crate::core::constants::KEY_BYTES;

/// Securely overwrites a byte slice with zeros using volatile writes so the
/// compiler cannot optimize away the wipe as a dead store.
pub fn zeroize_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, mutable reference within `buf`.
        unsafe {
            ptr::write_volatile(byte as *mut u8, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Securely overwrites a `u64` slice with zeros using volatile writes.
pub fn zeroize_u64_slice(buf: &mut [u64]) {
    for word in buf.iter_mut() {
        // SAFETY: `word` is a valid, aligned, mutable reference within `buf`.
        unsafe {
            ptr::write_volatile(word as *mut u64, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// A 256-bit secret key wrapper that redacts debug formatting and automatically
/// wipes its bytes from memory when dropped.
#[derive(Clone)]
pub struct SecretKey {
    bytes: [u8; KEY_BYTES],
}

impl SecretKey {
    /// Wraps a raw 32-byte key.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Exposes the underlying 32-byte array for cryptographic operations.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}
