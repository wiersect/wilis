//! Passphrase-Protected Secret Key Envelopes (`WENC` v1) & Local Public-Key Keyring
//! with Expiration & Revocation Certificates (`WKRN` v1).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::format::{
    decrypt_with_passphrase_and_keyfile, encrypt_with_passphrase_and_keyfile,
};
use crate::hash::{hash, hash_hex};
use crate::kdf::KdfParams;
use crate::kem::KemPublicKey;
use crate::sign::{SlhPublicKey, VerifyingKey};
use crate::utils::zeroize::{read_bounded_file, write_atomic_file, zeroize_bytes};

const WENC_MAGIC: [u8; 4] = *b"WENC";
const WENC_VERSION: u8 = 1;
const WENC_AAD: &[u8] = b"wilis-keywrap-v1";

const WKRN_MAGIC: [u8; 4] = *b"WKRN";
const WKRN_VERSION: u8 = 1;
const MAX_KEYRING_BYTES: usize = 8 * 1024 * 1024;

/// Encrypts a raw secret key blob (`.wks`, `.wsk`, `.wls`) at rest into a `WENC` v1 envelope.
pub fn wrap_secret_key(
    raw_secret_key: &[u8],
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
    params: KdfParams,
) -> Result<Vec<u8>> {
    if raw_secret_key.is_empty() {
        return Err(WilisError::InvalidKey("secret key payload is empty".into()));
    }
    let inner = encrypt_with_passphrase_and_keyfile(
        passphrase,
        keyfile_hash,
        raw_secret_key,
        WENC_AAD,
        params,
    )?;
    let mut out = Vec::with_capacity(5 + inner.len());
    out.extend_from_slice(&WENC_MAGIC);
    out.push(WENC_VERSION);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Returns `true` if `data` is a passphrase-protected `WENC` v1 secret key envelope.
#[inline]
pub fn is_wrapped_secret_key(data: &[u8]) -> bool {
    data.len() >= 5 && data[0..4] == WENC_MAGIC && data[4] == WENC_VERSION
}

/// Decrypts and authenticates a `WENC` v1 secret key envelope back into raw key bytes.
pub fn unwrap_secret_key(
    wrapped: &[u8],
    passphrase: &[u8],
    keyfile_hash: Option<&[u8; HASH_BYTES]>,
) -> Result<Vec<u8>> {
    if !is_wrapped_secret_key(wrapped) {
        return Err(WilisError::InvalidFormat(
            "expected passphrase-protected WENC v1 secret key envelope".into(),
        ));
    }
    decrypt_with_passphrase_and_keyfile(passphrase, keyfile_hash, &wrapped[5..], WENC_AAD)
}

/// Kind of public key stored inside a [`Keyring`] entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyKind {
    Kem = 1,
    SignStateful = 2,
    SignStateless = 3,
}

impl PublicKeyKind {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Kem),
            2 => Ok(Self::SignStateful),
            3 => Ok(Self::SignStateless),
            _ => Err(WilisError::InvalidFormat(format!("unknown keyring key kind: {v}"))),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Kem => "WilisKEM (WKP1)",
            Self::SignStateful => "WilisSign (WPK1)",
            Self::SignStateless => "WilisSLH (WLP1)",
        }
    }
}

/// Single trusted contact public key record inside [`Keyring`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringEntry {
    pub name: String,
    pub kind: PublicKeyKind,
    pub added_unix: u64,
    /// Optional expiration UNIX timestamp (`0` means no expiration).
    pub expires_unix: u64,
    pub revoked: bool,
    pub revoke_reason: String,
    pub key_bytes: Vec<u8>,
}

impl KeyringEntry {
    /// Returns the 32-char `WilisHash-256` fingerprint of the stored public key.
    pub fn fingerprint(&self) -> String {
        hash_hex(&self.key_bytes)[..32].to_string()
    }

    /// Returns `true` if the key is neither revoked nor past its expiration timestamp.
    pub fn is_usable_at(&self, now_unix: u64) -> bool {
        !self.revoked && (self.expires_unix == 0 || now_unix < self.expires_unix)
    }
}

/// Local trusted public-key keyring (`WKRN` v1) supporting expiration & revocation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Keyring {
    entries: BTreeMap<String, KeyringEntry>,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn detect_and_validate_pk(bytes: &[u8]) -> Result<PublicKeyKind> {
    if KemPublicKey::from_bytes(bytes).is_ok() {
        return Ok(PublicKeyKind::Kem);
    }
    if VerifyingKey::from_bytes(bytes).is_ok() {
        return Ok(PublicKeyKind::SignStateful);
    }
    if SlhPublicKey::from_bytes(bytes).is_ok() {
        return Ok(PublicKeyKind::SignStateless);
    }
    Err(WilisError::InvalidKey(
        "unrecognized or corrupted public key (expected WKP1, WPK1, or WLP1)".into(),
    ))
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates and adds (or replaces) a named public key in the keyring.
    pub fn add_key(&mut self, name: &str, key_bytes: Vec<u8>, expires_unix: u64) -> Result<()> {
        if name.is_empty() || name.len() > 256 || name.chars().any(|c| c.is_control()) {
            return Err(WilisError::InvalidParameters(
                "keyring contact name must be 1..=256 non-control chars".into(),
            ));
        }
        let kind = detect_and_validate_pk(&key_bytes)?;
        self.entries.insert(
            name.to_string(),
            KeyringEntry {
                name: name.to_string(),
                kind,
                added_unix: now_unix_secs(),
                expires_unix,
                revoked: false,
                revoke_reason: String::new(),
                key_bytes,
            },
        );
        Ok(())
    }

    /// Marks an existing contact key as revoked with an audit reason.
    pub fn revoke(&mut self, name: &str, reason: &str) -> Result<()> {
        if reason.len() > 512 || reason.chars().any(|c| c.is_control()) {
            return Err(WilisError::InvalidParameters(
                "revocation reason must be <= 512 non-control chars".into(),
            ));
        }
        let entry = self.entries.get_mut(name).ok_or_else(|| {
            WilisError::InvalidFormat(format!("keyring contact '{name}' not found"))
        })?;
        entry.revoked = true;
        entry.revoke_reason = reason.to_string();
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<&KeyringEntry> {
        self.entries.get(name)
    }

    pub fn list(&self) -> Vec<&KeyringEntry> {
        self.entries.values().collect()
    }

    /// Serializes the keyring to canonical `WKRN` v1 bytes with trailing `WilisHash-256` checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&WKRN_MAGIC);
        out.push(WKRN_VERSION);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        for e in self.entries.values() {
            let nb = e.name.as_bytes();
            let rb = e.revoke_reason.as_bytes();
            out.extend_from_slice(&(nb.len() as u32).to_le_bytes());
            out.extend_from_slice(nb);
            out.push(e.kind as u8);
            out.extend_from_slice(&e.added_unix.to_le_bytes());
            out.extend_from_slice(&e.expires_unix.to_le_bytes());
            out.push(if e.revoked { 1 } else { 0 });
            out.extend_from_slice(&(rb.len() as u32).to_le_bytes());
            out.extend_from_slice(rb);
            out.extend_from_slice(&(e.key_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&e.key_bytes);
        }
        let chk = hash(&out);
        out.extend_from_slice(&chk);
        out
    }

    /// Parses and integrity-checks a canonical `WKRN` v1 keyring file.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 9 + HASH_BYTES
            || data[0..4] != WKRN_MAGIC
            || data[4] != WKRN_VERSION
        {
            return Err(WilisError::InvalidFormat(
                "invalid or truncated WilisKeyring (WKRN) file".into(),
            ));
        }
        let body = &data[..data.len() - HASH_BYTES];
        let chk = &data[data.len() - HASH_BYTES..];
        if !crate::utils::constant_time::ct_eq(chk, &hash(body)) {
            return Err(WilisError::AuthenticationFailed);
        }

        let count = u32::from_le_bytes(body[5..9].try_into().expect("4 bytes")) as usize;
        let mut pos = 9usize;
        let mut kr = Self::new();

        for _ in 0..count {
            if body.len().saturating_sub(pos) < 4 {
                return Err(WilisError::InvalidFormat("truncated keyring name len".into()));
            }
            let nlen = u32::from_le_bytes(body[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if nlen == 0 || nlen > 256 || body.len().saturating_sub(pos) < nlen {
                return Err(WilisError::InvalidFormat("invalid keyring contact name".into()));
            }
            let name = String::from_utf8(body[pos..pos + nlen].to_vec())
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 keyring name".into()))?;
            if name.chars().any(|c| c.is_control()) || kr.entries.contains_key(&name) {
                return Err(WilisError::InvalidFormat(
                    "invalid or duplicate contact name in keyring".into(),
                ));
            }
            pos += nlen;

            if body.len().saturating_sub(pos) < 1 + 8 + 8 + 1 + 4 {
                return Err(WilisError::InvalidFormat("truncated keyring metadata".into()));
            }
            let kind = PublicKeyKind::from_u8(body[pos])?;
            pos += 1;
            let added_unix = u64::from_le_bytes(body[pos..pos + 8].try_into().expect("8 bytes"));
            pos += 8;
            let expires_unix = u64::from_le_bytes(body[pos..pos + 8].try_into().expect("8 bytes"));
            pos += 8;
            let revoked = match body[pos] {
                0 => false,
                1 => true,
                _ => return Err(WilisError::InvalidFormat("invalid keyring revoked flag".into())),
            };
            pos += 1;
            let rlen = u32::from_le_bytes(body[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if rlen > 512 || body.len().saturating_sub(pos) < rlen {
                return Err(WilisError::InvalidFormat("truncated keyring revoke reason".into()));
            }
            let revoke_reason = String::from_utf8(body[pos..pos + rlen].to_vec())
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 revoke reason".into()))?;
            pos += rlen;

            if body.len().saturating_sub(pos) < 4 {
                return Err(WilisError::InvalidFormat("truncated keyring key len".into()));
            }
            let klen = u32::from_le_bytes(body[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if klen == 0 || klen > 4096 || body.len().saturating_sub(pos) < klen {
                return Err(WilisError::InvalidFormat("invalid keyring key bytes".into()));
            }
            let key_bytes = body[pos..pos + klen].to_vec();
            pos += klen;
            let detected = detect_and_validate_pk(&key_bytes)?;
            if detected != kind {
                return Err(WilisError::InvalidFormat("keyring key kind mismatch".into()));
            }

            kr.entries.insert(
                name.clone(),
                KeyringEntry {
                    name,
                    kind,
                    added_unix,
                    expires_unix,
                    revoked,
                    revoke_reason,
                    key_bytes,
                },
            );
        }

        if pos != body.len() {
            return Err(WilisError::InvalidFormat("unexpected trailing bytes in keyring".into()));
        }
        Ok(kr)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut raw = self.to_bytes();
        let res = write_atomic_file(path, &raw, false);
        zeroize_bytes(&mut raw);
        res
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = read_bounded_file(path, MAX_KEYRING_BYTES)?;
        Self::from_bytes(&raw)
    }
}
