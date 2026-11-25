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
///
/// On `set` and `del`, preserves the vault's existing KDF parameters unless
/// `explicit_strength` was passed on the command line (preventing silent downgrade
/// of `high`/`paranoid` vaults to `interactive`).
pub fn run_vault(
    vault_path: &str,
    auth: AuthInput,
    action: VaultAction,
    explicit_strength: Option<KdfStrength>,
) -> Result<()> {
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
            let params = explicit_strength.unwrap_or(strength).to_params();
            vault.save_encrypted(path, pass, keyfile_hash, params)?;
            println!("Initialized encrypted WilisVault at '{vault_path}'");
            Ok(())
        }
        VaultAction::Set { name, value } => {
            let (mut vault, loaded_params) =
                Vault::load_encrypted_with_params(path, pass, keyfile_hash)?;
            vault.set(name.as_str(), value.as_str())?;
            let save_params = explicit_strength
                .map(|s| s.to_params())
                .unwrap_or(loaded_params);
            vault.save_encrypted(path, pass, keyfile_hash, save_params)?;
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
            let (mut vault, loaded_params) =
                Vault::load_encrypted_with_params(path, pass, keyfile_hash)?;
            if !vault.delete(name) {
                return Err(WilisError::InvalidFormat(format!(
                    "secret '{name}' not found in vault"
                )));
            }
            let save_params = explicit_strength
                .map(|s| s.to_params())
                .unwrap_or(loaded_params);
            vault.save_encrypted(path, pass, keyfile_hash, save_params)?;
            println!("Deleted secret '{name}' from '{vault_path}'");
            Ok(())
        }
    }
}
