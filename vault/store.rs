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
use crate::utils::zeroize::zeroize_bytes;

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
        self.entries.insert(k, value.into());
        Ok(())
    }

    /// Retrieves a secret value by `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|s| s.as_str())
    }

    /// Deletes a secret entry by `name`, returning `true` if it existed.
    pub fn delete(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
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
        let mut entries = BTreeMap::new();

        for _ in 0..count {
            if pos + 4 > data.len() {
                return Err(WilisError::InvalidFormat("truncated vault key length".into()));
            }
            let klen = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if pos + klen > data.len() {
                return Err(WilisError::InvalidFormat("truncated vault key bytes".into()));
            }
            let k = String::from_utf8(data[pos..pos + klen].to_vec())
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 vault key".into()))?;
            pos += klen;

            if pos + 4 > data.len() {
                return Err(WilisError::InvalidFormat("truncated vault value length".into()));
            }
            let vlen = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            if pos + vlen > data.len() {
                return Err(WilisError::InvalidFormat("truncated vault value bytes".into()));
            }
            let v = String::from_utf8(data[pos..pos + vlen].to_vec())
                .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 vault value".into()))?;
            pos += vlen;

            entries.insert(k, v);
        }

        if pos != data.len() {
            return Err(WilisError::InvalidFormat(
                "unexpected trailing bytes in vault payload".into(),
            ));
        }

        Ok(Self { entries })
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
        let encrypted = encrypt_with_passphrase_and_keyfile(
            passphrase,
            keyfile_hash,
            &raw,
            VAULT_AAD,
            params,
        )?;
        zeroize_bytes(&mut raw);

        // Atomic write via sibling temporary file
        let mut tmp_os = path.as_os_str().to_os_string();
        tmp_os.push(".tmp");
        let tmp_path = std::path::PathBuf::from(tmp_os);
        fs::write(&tmp_path, &encrypted)?;
        fs::rename(&tmp_path, path)?;
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
        let vault = Self::from_bytes(&raw)?;
        zeroize_bytes(&mut raw);
        Ok(vault)
    }
}
