//! Zero-dependency command-line interface for Wilis v0.4.3.

pub mod args;
pub mod audit_cmd;
pub mod bench_cmd;
pub mod dir_cmd;
pub mod file_cmd;
pub mod kem_cmd;
pub mod keygen_cmd;
pub mod mac_cmd;
pub mod sign_cmd;
pub mod split_cmd;
pub mod text_cmd;
pub mod vault_cmd;

use crate::cli::args::{parse_args, Command};
use crate::error::Result;

/// Parses CLI arguments and dispatches to the matching command handler.
pub fn run(raw_args: &[String]) -> Result<()> {
    match parse_args(raw_args)? {
        Command::Help => {
            println!("{}", args::usage_text());
            Ok(())
        }
        Command::EncryptText {
            auth,
            aad,
            plaintext,
        } => text_cmd::run_encrypt(auth, &aad, &plaintext),
        Command::DecryptText {
            auth,
            aad,
            ciphertext_b64,
        } => text_cmd::run_decrypt(auth, &aad, &ciphertext_b64),
        Command::EncryptFile {
            auth,
            aad,
            input_path,
            output_path,
        } => file_cmd::run_encrypt(auth, &aad, &input_path, &output_path),
        Command::DecryptFile {
            auth,
            aad,
            input_path,
            output_path,
        } => file_cmd::run_decrypt(auth, &aad, &input_path, &output_path),
        Command::EncryptDir {
            auth,
            aad,
            dir_path,
            output_file,
        } => dir_cmd::run_encrypt_dir(auth, &aad, &dir_path, &output_file),
        Command::DecryptDir {
            auth,
            aad,
            input_file,
            out_dir,
        } => dir_cmd::run_decrypt_dir(auth, &aad, &input_file, &out_dir),
        Command::KemKeygen { out_prefix } => kem_cmd::run_kem_keygen(&out_prefix),
        Command::PubEncrypt {
            pk_path,
            aad,
            input_path,
            output_path,
        } => kem_cmd::run_pub_encrypt(&pk_path, &aad, &input_path, &output_path),
        Command::PubDecrypt {
            sk_path,
            aad,
            input_path,
            output_path,
        } => kem_cmd::run_pub_decrypt(&sk_path, &aad, &input_path, &output_path),
        Command::Vault {
            vault_path,
            auth,
            action,
        } => vault_cmd::run_vault(&vault_path, auth, action),
        Command::SignKeygen { out_prefix, height } => sign_cmd::run_sign_keygen(&out_prefix, height),
        Command::SignFile {
            sk_path,
            input_path,
            sig_out_path,
        } => sign_cmd::run_sign_file(&sk_path, &input_path, &sig_out_path),
        Command::VerifyFile {
            pk_path,
            input_path,
            sig_path,
        } => sign_cmd::run_verify_file(&pk_path, &input_path, &sig_path),
        Command::SplitKey {
            secret_hex,
            total,
            threshold,
        } => split_cmd::run_split_key(&secret_hex, total, threshold),
        Command::CombineKey { shares } => split_cmd::run_combine_key(&shares),
        Command::Mac {
            key,
            file_path,
            text,
        } => mac_cmd::run_mac(key, file_path.as_deref(), text.as_deref()),
        Command::MacVerify {
            key,
            tag_hex,
            file_path,
            text,
        } => mac_cmd::run_mac_verify(key, &tag_hex, file_path.as_deref(), text.as_deref()),
        Command::Rand { bytes } => mac_cmd::run_rand(bytes),
        Command::Keygen => keygen_cmd::run_keygen(),
        Command::HashText { text } => keygen_cmd::run_hash_text(&text),
        Command::HashFile { path } => keygen_cmd::run_hash_file(&path),
        Command::Bench => bench_cmd::run_bench(),
        Command::Audit => audit_cmd::run_audit(),
    }
}
