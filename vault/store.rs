//! Encrypted key-value secret store (`WVLT` v1) with atomic save and memory wiping.

use std::collections::BTreeMap;
use std::path::Path;

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::format::{
    decrypt_with_passphrase_and_keyfile, encrypt_with_passphrase_and_keyfile, ContainerHeader,
    KeyMode,
};
use crate::kdf::KdfParams;
use crate::protocols::totp::{decode_base32, generate_totp_at, generate_totp_now};
use crate::utils::armor::{armor_decode, armor_encode};
use crate::utils::zeroize::{read_bounded_file, write_secret_file, zeroize_bytes};

const VAULT_ARMOR_LABEL: &str = "WILIS VAULT";

const VAULT_MAGIC: [u8; 4] = *b"WVLT";
const VAULT_VERSION: u8 = 1;
const VAULT_AAD: &[u8] = b"wilis-vault-v1";
const MAX_VAULT_KEY_BYTES: usize = 4096;
const MAX_VAULT_VAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_VAULT_FILE_BYTES: usize = 128 * 1024 * 1024;

fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_VAULT_KEY_BYTES {
        return Err(WilisError::InvalidParameters(
            "vault secret name must be 1..=4096 bytes".into(),
        ));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(WilisError::InvalidParameters(
            "vault secret name must not contain control characters".into(),
        ));
    }
    Ok(())
}

/// In-memory representation of a decrypted `WilisVault` secret store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Vault {
    entries: BTreeMap<String, String>,
}

impl Vault {
    /// Creates a new empty vault.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Inserts or updates a secret entry by `name`.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) -> Result<()> {
        let k = name.into();
        let mut v = value.into();
        if let Err(e) = validate_secret_name(&k) {
            // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { v.as_bytes_mut() });
            return Err(e);
        }
        if v.len() > MAX_VAULT_VAL_BYTES {
            zeroize_bytes(unsafe { v.as_bytes_mut() });
            return Err(WilisError::InvalidParameters(
                "vault secret value exceeds 64 MiB safety limit".into(),
            ));
        }
        if let Some(mut old) = self.entries.insert(k, v) {
            // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { old.as_bytes_mut() });
        }
        Ok(())
    }

    /// Retrieves a secret value by `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|s| s.as_str())
    }

    /// Deletes a secret entry by `name`, returning `true` if it existed.
    pub fn delete(&mut self, name: &str) -> bool {
        if let Some(mut old) = self.entries.remove(name) {
            // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { old.as_bytes_mut() });
            true
        } else {
            false
        }
    }

    /// Lists all secret names in sorted order.
    pub fn list_names(&self) -> Vec<&str> {
        self.entries.keys().map(|k| k.as_str()).collect()
    }

    /// Searches secret names by case-insensitive substring (never exposes values).
    pub fn search(&self, query: &str) -> Vec<&str> {
        let q = query.to_ascii_lowercase();
        self.entries
            .keys()
            .filter(|k| k.to_ascii_lowercase().contains(&q))
            .map(|k| k.as_str())
            .collect()
    }

    /// Iterates over all `(name, value)` pairs in deterministic sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Merges all entries from `other` into `self` (updating existing names).
    pub fn merge_from(&mut self, other: &Vault) -> Result<usize> {
        let mut count = 0usize;
        for (k, v) in other.iter() {
            self.set(k, v)?;
            count += 1;
        }
        Ok(count)
    }

    /// Extracts a Base32 TOTP secret stored at `name` (supporting raw Base32 or `otpauth://...secret=...`
    /// URIs) and computes `(code, seconds_remaining)` at `unix_secs`.
    pub fn totp_at(
        &self,
        name: &str,
        unix_secs: u64,
        period: u64,
        digits: u32,
    ) -> Result<(String, u64)> {
        let raw_val = self.get(name).ok_or_else(|| {
            WilisError::InvalidFormat(format!("secret '{name}' not found in vault"))
        })?;
        let b32 = extract_totp_secret_field(raw_val);
        let mut secret = decode_base32(b32)?;
        let res = generate_totp_at(&secret, unix_secs, period, digits);
        zeroize_bytes(&mut secret);
        res
    }

    /// Computes the current wall-clock `WilisTOTP` code `(code, seconds_remaining)` for `name`.
    pub fn totp_now(&self, name: &str, period: u64, digits: u32) -> Result<(String, u64)> {
        let raw_val = self.get(name).ok_or_else(|| {
            WilisError::InvalidFormat(format!("secret '{name}' not found in vault"))
        })?;
        let b32 = extract_totp_secret_field(raw_val);
        let mut secret = decode_base32(b32)?;
        let res = generate_totp_now(&secret, period, digits);
        zeroize_bytes(&mut secret);
        res
    }

    /// Exports the vault as an authenticated ASCII-armored (`WILIS VAULT`) encrypted backup.
    pub fn export_armored(
        &self,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
        params: KdfParams,
    ) -> Result<String> {
        let mut raw = self.to_bytes();
        let enc_res = encrypt_with_passphrase_and_keyfile(
            passphrase,
            keyfile_hash,
            &raw,
            VAULT_AAD,
            params,
        );
        zeroize_bytes(&mut raw);
        let encrypted = enc_res?;
        armor_encode(VAULT_ARMOR_LABEL, &encrypted)
    }

    /// Authenticates, decrypts, and imports a vault from an ASCII-armored (`WILIS VAULT`) backup.
    pub fn import_armored(
        armored: &str,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
    ) -> Result<Self> {
        let (_, encrypted) = armor_decode(armored, Some(VAULT_ARMOR_LABEL))?;
        let mut raw = decrypt_with_passphrase_and_keyfile(
            passphrase,
            keyfile_hash,
            &encrypted,
            VAULT_AAD,
        )?;
        let res = Self::from_bytes(&raw);
        zeroize_bytes(&mut raw);
        res
    }

    /// Returns the number of stored secrets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the vault contains no secrets.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serializes the vault entries into canonical `WVLT` v1 binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VAULT_MAGIC);
        out.push(VAULT_VERSION);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        for (k, v) in &self.entries {
            let kb = k.as_bytes();
            let vb = v.as_bytes();
            out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
            out.extend_from_slice(kb);
            out.extend_from_slice(&(vb.len() as u32).to_le_bytes());
            out.extend_from_slice(vb);
        }
        out
    }

    /// Parses a canonical `WVLT` v1 binary payload.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 9 || data[0..4] != VAULT_MAGIC || data[4] != VAULT_VERSION {
            return Err(WilisError::InvalidFormat(
                "invalid or corrupted WilisVault payload".into(),
            ));
        }
        let count = u32::from_le_bytes(data[5..9].try_into().expect("4 bytes")) as usize;
        let mut pos = 9usize;
        // Construct Vault immediately so Drop zeroizes already-parsed secrets on any parse error.
        let mut vault = Self::new();

        for _ in 0..count {
            if data.len().saturating_sub(pos) < 4 {
                return Err(WilisError::InvalidFormat("truncated vault key length".into()));
            }
            let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if klen == 0 || klen > MAX_VAULT_KEY_BYTES || data.len().saturating_sub(pos) < klen {
                return Err(WilisError::InvalidFormat("invalid or truncated vault key bytes".into()));
            }
            let k = String::from_utf8(data[pos..pos + klen].to_vec())
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 vault key".into()))?;
            validate_secret_name(&k).map_err(|_| {
                WilisError::InvalidFormat("invalid control character in vault secret name".into())
            })?;
            pos += klen;

            if data.len().saturating_sub(pos) < 4 {
                return Err(WilisError::InvalidFormat("truncated vault value length".into()));
            }
            let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if vlen > MAX_VAULT_VAL_BYTES || data.len().saturating_sub(pos) < vlen {
                return Err(WilisError::InvalidFormat("invalid or truncated vault value bytes".into()));
            }
            let mut v = String::from_utf8(data[pos..pos + vlen].to_vec()).map_err(|err| {
                let mut raw = err.into_bytes();
                zeroize_bytes(&mut raw);
                WilisError::InvalidEncoding("non-UTF-8 vault value".into())
            })?;
            pos += vlen;

            if vault.entries.contains_key(&k) {
                // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
                zeroize_bytes(unsafe { v.as_bytes_mut() });
                return Err(WilisError::InvalidFormat(format!(
                    "duplicate secret key '{k}' rejected in vault payload"
                )));
            }
            vault.set(k, v)?;
        }

        if pos != data.len() {
            return Err(WilisError::InvalidFormat(
                "unexpected trailing bytes in vault payload".into(),
            ));
        }

        Ok(vault)
    }

    /// Atomically encrypts and saves the vault to `path` via a temporary file + rename.
    pub fn save_encrypted(
        &self,
        path: &Path,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
        params: KdfParams,
    ) -> Result<()> {
        let mut raw = self.to_bytes();
        let enc_res = encrypt_with_passphrase_and_keyfile(
            passphrase,
            keyfile_hash,
            &raw,
            VAULT_AAD,
            params,
        );
        zeroize_bytes(&mut raw);
        let encrypted = enc_res?;

        // Atomic write via CSPRNG-named O_EXCL sibling temp file (mode 0600 on Unix + sync_all)
        write_secret_file(path, &encrypted)?;
        Ok(())
    }

    /// Loads, authenticates, and decrypts a vault from `path`, returning both the [`Vault`]
    /// and the [`KdfParams`] stored in its container header so updates preserve KDF strength.
    pub fn load_encrypted_with_params(
        path: &Path,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
    ) -> Result<(Self, KdfParams)> {
        let encrypted = read_bounded_file(path, MAX_VAULT_FILE_BYTES)?;
        let (header, _) = ContainerHeader::parse(&encrypted)?;
        let params = match header.mode {
            KeyMode::Passphrase { params, .. } => params,
            KeyMode::RawKey => {
                return Err(WilisError::InvalidFormat(
                    "vault container must use passphrase mode".into(),
                ));
            }
        };
        let mut raw = decrypt_with_passphrase_and_keyfile(
            passphrase,
            keyfile_hash,
            &encrypted,
            VAULT_AAD,
        )?;
        let vault_res = Self::from_bytes(&raw);
        zeroize_bytes(&mut raw);
        Ok((vault_res?, params))
    }

    /// Loads, authenticates, and decrypts a vault from `path`.
    pub fn load_encrypted(
        path: &Path,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
    ) -> Result<Self> {
        Self::load_encrypted_with_params(path, passphrase, keyfile_hash).map(|(v, _)| v)
    }
}

fn extract_totp_secret_field(val: &str) -> &str {
    let trimmed = val.trim();
    if let Some(q_idx) = trimmed.find('?') {
        let query = &trimmed[q_idx + 1..];
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("secret") {
                    return v;
                }
            }
        }
    }
    trimmed
}

impl Drop for Vault {
    fn drop(&mut self) {
        for val in self.entries.values_mut() {
            // SAFETY: Overwriting UTF-8 string bytes with 0x00 (valid ASCII NUL) preserves UTF-8 validity.
            let bytes = unsafe { val.as_bytes_mut() };
            zeroize_bytes(bytes);
        }
    }
}
