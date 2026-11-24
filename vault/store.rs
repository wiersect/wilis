//! Encrypted key-value secret store (`WVLT` v1) with atomic save and memory wiping.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::format::{
    decrypt_with_passphrase_and_keyfile, encrypt_with_passphrase_and_keyfile,
};
use crate::kdf::KdfParams;
use crate::utils::zeroize::{write_secret_file, zeroize_bytes};

const VAULT_MAGIC: [u8; 4] = *b"WVLT";
const VAULT_VERSION: u8 = 1;
const VAULT_AAD: &[u8] = b"wilis-vault-v1";

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
        if k.is_empty() {
            return Err(WilisError::InvalidParameters(
                "vault secret name must not be empty".into(),
            ));
        }
        if let Some(mut old) = self.entries.insert(k, value.into()) {
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
            if data.len().saturating_sub(pos) < klen {
                return Err(WilisError::InvalidFormat("truncated vault key bytes".into()));
            }
            let k = String::from_utf8(data[pos..pos + klen].to_vec())
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 vault key".into()))?;
            if k.is_empty() {
                return Err(WilisError::InvalidFormat("empty vault secret name".into()));
            }
            pos += klen;

            if data.len().saturating_sub(pos) < 4 {
                return Err(WilisError::InvalidFormat("truncated vault value length".into()));
            }
            let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if data.len().saturating_sub(pos) < vlen {
                return Err(WilisError::InvalidFormat("truncated vault value bytes".into()));
            }
            let v = String::from_utf8(data[pos..pos + vlen].to_vec()).map_err(|err| {
                let mut raw = err.into_bytes();
                zeroize_bytes(&mut raw);
                WilisError::InvalidEncoding("non-UTF-8 vault value".into())
            })?;
            pos += vlen;

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

    /// Loads, authenticates, and decrypts a vault from `path`.
    pub fn load_encrypted(
        path: &Path,
        passphrase: &[u8],
        keyfile_hash: Option<&[u8; HASH_BYTES]>,
    ) -> Result<Self> {
        let encrypted = fs::read(path)?;
        let mut raw = decrypt_with_passphrase_and_keyfile(
            passphrase,
            keyfile_hash,
            &encrypted,
            VAULT_AAD,
        )?;
        let vault_res = Self::from_bytes(&raw);
        zeroize_bytes(&mut raw);
        vault_res
    }
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
