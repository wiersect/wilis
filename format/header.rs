//! Binary header serialization and parsing for `WILS` v1 (single-shot) and
//! `WILS` v2 (chunked streaming) container formats.

use std::io::Read;

use crate::core::constants::{NONCE_BYTES, SALT_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfParams;
use crate::stream::chunk_nonce::{MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};

/// Four-byte ASCII magic header identifying a Wilis container.
pub const MAGIC_BYTES: [u8; 4] = *b"WILS";

/// Version 1: Single-shot authenticated container (ideal for messages / short payloads).
pub const FORMAT_VERSION: u8 = 1;

/// Version 2: Constant-memory chunked streaming container (for arbitrary multi-GB files).
pub const FORMAT_VERSION_V2: u8 = 2;

/// Keying mode stored in the container header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    /// Key derived from a passphrase (+ optional 2FA keyfile) via memory-hard `WilisKDF`.
    Passphrase {
        params: KdfParams,
        salt: [u8; SALT_BYTES],
    },
    /// Direct 256-bit raw secret key.
    RawKey,
}

/// Parsed container header preceding the ciphertext/chunks and authentication tag(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHeader {
    pub version: u8,
    pub mode: KeyMode,
    pub nonce: [u8; NONCE_BYTES],
    /// Present for `FORMAT_VERSION_V2` streaming containers; `None` for v1.
    pub chunk_size: Option<u32>,
}

impl ContainerHeader {
    /// Serializes the header into its canonical byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(68);
        out.extend_from_slice(&MAGIC_BYTES);
        out.push(self.version);

        match self.mode {
            KeyMode::Passphrase { params, salt } => {
                out.push(0x01);
                out.extend_from_slice(&params.memory_blocks.to_le_bytes());
                out.extend_from_slice(&params.passes.to_le_bytes());
                out.extend_from_slice(&salt);
            }
            KeyMode::RawKey => {
                out.push(0x02);
            }
        }

        out.extend_from_slice(&self.nonce);

        if self.version == FORMAT_VERSION_V2 {
            let cs = self.chunk_size.expect("v2 header must carry chunk_size");
            out.extend_from_slice(&cs.to_le_bytes());
        }

        out
    }

    /// Parses a header from the prefix of `data`, returning `(header, header_byte_len)`.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 6 {
            return Err(WilisError::InvalidFormat(
                "container is too short to hold header prefix".to_string(),
            ));
        }

        if data[0..4] != MAGIC_BYTES {
            return Err(WilisError::InvalidFormat(
                "invalid magic bytes (expected 'WILS')".to_string(),
            ));
        }

        let version = data[4];
        if version != FORMAT_VERSION && version != FORMAT_VERSION_V2 {
            return Err(WilisError::InvalidFormat(format!(
                "unsupported container version: {version}"
            )));
        }
        let extra_v2 = if version == FORMAT_VERSION_V2 { 4 } else { 0 };

        let mode_byte = data[5];
        match mode_byte {
            0x01 => {
                let expected_len = 6 + 4 + 4 + SALT_BYTES + NONCE_BYTES + extra_v2;
                if data.len() < expected_len {
                    return Err(WilisError::InvalidFormat(
                        "truncated passphrase-mode container header".to_string(),
                    ));
                }
                let memory_blocks = u32::from_le_bytes(data[6..10].try_into().expect("4 bytes"));
                let passes = u32::from_le_bytes(data[10..14].try_into().expect("4 bytes"));
                let params = KdfParams {
                    memory_blocks,
                    passes,
                };
                params.validate()?;

                let mut salt = [0u8; SALT_BYTES];
                salt.copy_from_slice(&data[14..14 + SALT_BYTES]);

                let nonce_start = 14 + SALT_BYTES;
                let mut nonce = [0u8; NONCE_BYTES];
                nonce.copy_from_slice(&data[nonce_start..nonce_start + NONCE_BYTES]);

                let chunk_size = if version == FORMAT_VERSION_V2 {
                    let cs_start = nonce_start + NONCE_BYTES;
                    let cs = u32::from_le_bytes(data[cs_start..cs_start + 4].try_into().expect("4 bytes"));
                    validate_header_chunk_size(cs)?;
                    Some(cs)
                } else {
                    None
                };

                Ok((
                    Self {
                        version,
                        mode: KeyMode::Passphrase { params, salt },
                        nonce,
                        chunk_size,
                    },
                    expected_len,
                ))
            }
            0x02 => {
                let expected_len = 6 + NONCE_BYTES + extra_v2;
                if data.len() < expected_len {
                    return Err(WilisError::InvalidFormat(
                        "truncated raw-key-mode container header".to_string(),
                    ));
                }
                let mut nonce = [0u8; NONCE_BYTES];
                nonce.copy_from_slice(&data[6..6 + NONCE_BYTES]);

                let chunk_size = if version == FORMAT_VERSION_V2 {
                    let cs_start = 6 + NONCE_BYTES;
                    let cs = u32::from_le_bytes(data[cs_start..cs_start + 4].try_into().expect("4 bytes"));
                    validate_header_chunk_size(cs)?;
                    Some(cs)
                } else {
                    None
                };

                Ok((
                    Self {
                        version,
                        mode: KeyMode::RawKey,
                        nonce,
                        chunk_size,
                    },
                    expected_len,
                ))
            }
            other => Err(WilisError::InvalidFormat(format!(
                "unknown container key mode: 0x{other:02x}"
            ))),
        }
    }

    /// Reads and parses a container header directly from a streaming `Read` source,
    /// returning `(header, exact_serialized_header_bytes)`.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<(Self, Vec<u8>)> {
        let mut prefix = [0u8; 6];
        reader.read_exact(&mut prefix).map_err(|_| {
            WilisError::InvalidFormat("truncated stream before header prefix".to_string())
        })?;

        if prefix[0..4] != MAGIC_BYTES {
            return Err(WilisError::InvalidFormat(
                "invalid magic bytes (expected 'WILS')".to_string(),
            ));
        }

        let version = prefix[4];
        if version != FORMAT_VERSION && version != FORMAT_VERSION_V2 {
            return Err(WilisError::InvalidFormat(format!(
                "unsupported container version: {version}"
            )));
        }
        let extra_v2 = if version == FORMAT_VERSION_V2 { 4 } else { 0 };
        let remaining = match prefix[5] {
            0x01 => 4 + 4 + SALT_BYTES + NONCE_BYTES + extra_v2,
            0x02 => NONCE_BYTES + extra_v2,
            other => {
                return Err(WilisError::InvalidFormat(format!(
                    "unknown container key mode: 0x{other:02x}"
                )));
            }
        };

        let mut raw = vec![0u8; 6 + remaining];
        raw[0..6].copy_from_slice(&prefix);
        reader.read_exact(&mut raw[6..]).map_err(|_| {
            WilisError::InvalidFormat("truncated stream inside container header".to_string())
        })?;

        let (header, _) = Self::parse(&raw)?;
        Ok((header, raw))
    }
}

fn validate_header_chunk_size(cs: u32) -> Result<()> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&cs) {
        return Err(WilisError::InvalidFormat(format!(
            "invalid header chunk_size {cs} (must be in {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE})"
        )));
    }
    Ok(())
}
