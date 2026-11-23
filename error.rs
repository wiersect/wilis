//! Error types for the Wilis cryptographic suite.

use std::fmt;
use std::io;

/// Unified error type returned by Wilis library and CLI operations.
#[derive(Debug)]
pub enum WilisError {
    /// Authentication tag verification failed (tampered data, wrong key, or wrong AAD).
    AuthenticationFailed,
    /// Invalid key length or malformed hex key input.
    InvalidKey(String),
    /// Invalid nonce or salt length.
    InvalidNonce(String),
    /// Malformed or unsupported encrypted container format.
    InvalidFormat(String),
    /// Malformed Base64 or Hex encoding.
    InvalidEncoding(String),
    /// Invalid KDF parameters (e.g., zero iterations or invalid memory cost).
    InvalidParameters(String),
    /// Operating system CSPRNG failure.
    RandomSourceError(String),
    /// Command-line argument error.
    CliUsage(String),
    /// Underlying filesystem or I/O error.
    Io(io::Error),
}

impl fmt::Display for WilisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WilisError::AuthenticationFailed => {
                write!(
                    f,
                    "authentication failed: ciphertext, header, associated data, or key is invalid"
                )
            }
            WilisError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            WilisError::InvalidNonce(msg) => write!(f, "invalid nonce: {msg}"),
            WilisError::InvalidFormat(msg) => write!(f, "invalid container format: {msg}"),
            WilisError::InvalidEncoding(msg) => write!(f, "invalid encoding: {msg}"),
            WilisError::InvalidParameters(msg) => write!(f, "invalid parameters: {msg}"),
            WilisError::RandomSourceError(msg) => write!(f, "random source error: {msg}"),
            WilisError::CliUsage(msg) => write!(f, "usage error: {msg}"),
            WilisError::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for WilisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WilisError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for WilisError {
    fn from(err: io::Error) -> Self {
        WilisError::Io(err)
    }
}

/// Convenience result alias used across Wilis.
pub type Result<T> = std::result::Result<T, WilisError>;
