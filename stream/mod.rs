//! Constant-memory Chunked Streaming AEAD (`WILS` v2) for arbitrary multi-gigabyte files.
//!
//! Security guarantees per chunk:
//! - Unique nonce per chunk derived from `(base_nonce, chunk_index)`.
//! - Every chunk authenticates `(header_digest, chunk_index, is_final_chunk, user_aad)`.
//! - Truncation, reordering, duplication, or single-bit tampering anywhere in the stream
//!   is immediately detected and rejected.

pub mod chunk_nonce;
pub mod decrypt_stream;
pub mod encrypt_stream;

pub use chunk_nonce::DEFAULT_CHUNK_SIZE;
pub use decrypt_stream::{decrypt_stream_with_key, decrypt_stream_with_passphrase};
pub use encrypt_stream::{encrypt_stream_with_key, encrypt_stream_with_passphrase};
