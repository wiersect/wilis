//! CLI handlers for `WilisVault` encrypted local secret manager
//! (`vault init|set|get|list|del|rekey|search|totp|export|import`).

use std::path::Path;

use crate::cli::args::{AuthInput, VaultAction};
use crate::error::{Result, WilisError};
use crate::kdf::KdfStrength;
use crate::utils::zeroize::{read_bounded_file, write_secret_file};
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
        VaultAction::Search { query } => {
            let vault = Vault::load_encrypted(path, pass, keyfile_hash)?;
            let matches = vault.search(query);
            if matches.is_empty() {
                println!("(no entries matching '{query}')");
            } else {
                for name in matches {
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
        VaultAction::Rekey {
            new_pass,
            new_keyfile_hash,
            new_strength,
        } => {
            let (vault, loaded_params) =
                Vault::load_encrypted_with_params(path, pass, keyfile_hash)?;
            let save_params = new_strength
                .or(explicit_strength)
                .map(|s| s.to_params())
                .unwrap_or(loaded_params);
            let target_pass = new_pass
                .as_deref()
                .map(|s| s.as_bytes())
                .unwrap_or(pass);
            let target_kf = match new_keyfile_hash {
                Some(h) => Some(h),
                None => keyfile_hash,
            };
            vault.save_encrypted(path, target_pass, target_kf, save_params)?;
            println!(
                "Rekeyed WilisVault '{vault_path}' ({} entries, {} KDF blocks, {} passes)",
                vault.len(),
                save_params.memory_blocks,
                save_params.passes
            );
            Ok(())
        }
        VaultAction::Totp {
            name,
            period,
            digits,
        } => {
            let vault = Vault::load_encrypted(path, pass, keyfile_hash)?;
            let (code, remaining) = vault.totp_now(name, *period, *digits)?;
            println!("{code} (valid for {remaining}s)");
            Ok(())
        }
        VaultAction::Export { out_path } => {
            let (vault, loaded_params) =
                Vault::load_encrypted_with_params(path, pass, keyfile_hash)?;
            let export_params = explicit_strength
                .map(|s| s.to_params())
                .unwrap_or(loaded_params);
            let armored = vault.export_armored(pass, keyfile_hash, export_params)?;
            write_secret_file(Path::new(out_path), armored.as_bytes())?;
            println!(
                "Exported encrypted ASCII-armored vault backup ({} entries) -> '{out_path}'",
                vault.len()
            );
            Ok(())
        }
        VaultAction::Import { in_path, merge } => {
            let raw = read_bounded_file(Path::new(in_path), 64 * 1024 * 1024)?;
            let armored = std::str::from_utf8(&raw)
                .map_err(|_| WilisError::InvalidEncoding("armored backup must be valid UTF-8".into()))?;
            let imported = Vault::import_armored(armored, pass, keyfile_hash)?;

            if *merge && path.exists() {
                let (mut existing, loaded_params) =
                    Vault::load_encrypted_with_params(path, pass, keyfile_hash)?;
                let merged = existing.merge_from(&imported)?;
                let save_params = explicit_strength
                    .map(|s| s.to_params())
                    .unwrap_or(loaded_params);
                existing.save_encrypted(path, pass, keyfile_hash, save_params)?;
                println!(
                    "Merged {merged} imported secret(s) into '{vault_path}' ({} total entries)",
                    existing.len()
                );
            } else {
                let save_params = explicit_strength.unwrap_or(strength).to_params();
                imported.save_encrypted(path, pass, keyfile_hash, save_params)?;
                println!(
                    "Imported encrypted backup '{in_path}' -> '{vault_path}' ({} entries)",
                    imported.len()
                );
            }
            Ok(())
        }
    }
}
