//! CLI handlers for `WilisVault` encrypted local secret manager (`vault init|set|get|list|del`).

use std::path::Path;

use crate::cli::args::{AuthInput, VaultAction};
use crate::error::{Result, WilisError};
use crate::kdf::KdfStrength;
use crate::vault::Vault;

fn extract_pass_auth(auth: &AuthInput) -> Result<(&[u8], Option<&[u8; 32]>, KdfStrength)> {
    match auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => Ok((passphrase.as_bytes(), keyfile_hash.as_ref(), *strength)),
        AuthInput::RawKey(_) => Err(WilisError::CliUsage(
            "vault commands require passphrase authentication (--pass or --pass-prompt)".into(),
        )),
    }
}

/// Executes a `vault` subcommand against an encrypted `.wils` vault file.
pub fn run_vault(vault_path: &str, auth: AuthInput, action: VaultAction) -> Result<()> {
    let (pass, keyfile_hash, strength) = extract_pass_auth(&auth)?;
    let path = Path::new(vault_path);

    match &action {
        VaultAction::Init => {
            if std::fs::symlink_metadata(path).is_ok() {
                return Err(WilisError::InvalidFormat(format!(
                    "vault '{}' already exists",
                    vault_path
                )));
            }
            let vault = Vault::new();
            vault.save_encrypted(path, pass, keyfile_hash, strength.to_params())?;
            println!("Initialized encrypted WilisVault at '{vault_path}'");
            Ok(())
        }
        VaultAction::Set { name, value } => {
            let mut vault = Vault::load_encrypted(path, pass, keyfile_hash)?;
            vault.set(name.as_str(), value.as_str())?;
            vault.save_encrypted(path, pass, keyfile_hash, strength.to_params())?;
            println!(
                "Saved secret '{name}' in '{vault_path}' ({} total entries)",
                vault.len()
            );
            Ok(())
        }
        VaultAction::Get { name } => {
            let vault = Vault::load_encrypted(path, pass, keyfile_hash)?;
            match vault.get(name) {
                Some(val) => {
                    println!("{val}");
                    Ok(())
                }
                None => Err(WilisError::InvalidFormat(format!(
                    "secret '{name}' not found in vault"
                ))),
            }
        }
        VaultAction::List => {
            let vault = Vault::load_encrypted(path, pass, keyfile_hash)?;
            if vault.is_empty() {
                println!("(vault is empty)");
            } else {
                for name in vault.list_names() {
                    println!("{name}");
                }
            }
            Ok(())
        }
        VaultAction::Delete { name } => {
            let mut vault = Vault::load_encrypted(path, pass, keyfile_hash)?;
            if !vault.delete(name) {
                return Err(WilisError::InvalidFormat(format!(
                    "secret '{name}' not found in vault"
                )));
            }
            vault.save_encrypted(path, pass, keyfile_hash, strength.to_params())?;
            println!("Deleted secret '{name}' from '{vault_path}'");
            Ok(())
        }
    }
}
