//! Zero-dependency command-line interface for Wilis v0.6.0.

pub mod args;
pub mod audit_cmd;
pub mod bench_cmd;
pub mod dir_cmd;
pub mod extra_cmd;
pub mod file_cmd;
pub mod inspect_cmd;
pub mod kem_cmd;
pub mod keygen_cmd;
pub mod mac_cmd;
pub mod sign_cmd;
pub mod split_cmd;
pub mod text_cmd;
pub mod vault_cmd;

use crate::cli::args::{parse_args, Command};
use crate::error::Result;
use crate::utils::zeroize::zeroize_bytes;

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
            mut plaintext,
            pad_block,
            armor,
        } => {
            let res = text_cmd::run_encrypt_ex(auth, &aad, &plaintext, pad_block, armor);
            // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { plaintext.as_bytes_mut() });
            res
        }
        Command::DecryptText {
            auth,
            aad,
            ciphertext_b64,
            unpad,
        } => text_cmd::run_decrypt_ex(auth, &aad, &ciphertext_b64, unpad),
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
            compress,
        } => dir_cmd::run_encrypt_dir(auth, &aad, &dir_path, &output_file, compress),
        Command::DecryptDir {
            auth,
            aad,
            input_file,
            out_dir,
        } => dir_cmd::run_decrypt_dir(auth, &aad, &input_file, &out_dir),
        Command::KemKeygen { out_prefix } => kem_cmd::run_kem_keygen(&out_prefix),
        Command::PubEncrypt {
            pk_paths,
            aad,
            input_path,
            output_path,
            armor,
        } => kem_cmd::run_pub_encrypt_multi(&pk_paths, &aad, &input_path, &output_path, armor),
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
            explicit_strength,
        } => vault_cmd::run_vault(&vault_path, auth, action, explicit_strength),
        Command::SignKeygen { out_prefix, height } => sign_cmd::run_sign_keygen(&out_prefix, height),
        Command::SignFile {
            sk_path,
            input_path,
            sig_out_path,
            armor,
        } => sign_cmd::run_sign_file_ex(&sk_path, &input_path, &sig_out_path, armor),
        Command::VerifyFile {
            pk_path,
            input_path,
            sig_path,
        } => sign_cmd::run_verify_file(&pk_path, &input_path, &sig_path),
        Command::SlhKeygen { out_prefix } => extra_cmd::run_slh_keygen(&out_prefix),
        Command::SlhSign {
            sk_path,
            input_path,
            sig_out_path,
            armor,
        } => extra_cmd::run_slh_sign(&sk_path, &input_path, &sig_out_path, armor),
        Command::SlhVerify {
            pk_path,
            input_path,
            sig_path,
        } => extra_cmd::run_slh_verify(&pk_path, &input_path, &sig_path),
        Command::SplitKey {
            mut secret_hex,
            total,
            threshold,
        } => {
            let res = split_cmd::run_split_key(&secret_hex, total, threshold);
            // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { secret_hex.as_bytes_mut() });
            res
        }
        Command::CombineKey { mut shares } => {
            let res = split_cmd::run_combine_key(&shares);
            for s in &mut shares {
                // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
                zeroize_bytes(unsafe { s.as_bytes_mut() });
            }
            res
        }
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
        Command::Passgen {
            mode,
            length,
            count,
        } => extra_cmd::run_passgen(mode, length, count),
        Command::MnemonicEncode { key_hex } => extra_cmd::run_mnemonic_encode(key_hex.as_str()),
        Command::MnemonicDecode { phrase } => extra_cmd::run_mnemonic_decode(phrase.as_str()),
        Command::KeyProtect {
            in_path,
            out_path,
            auth,
        } => extra_cmd::run_key_protect(&in_path, &out_path, auth),
        Command::KeyUnlock {
            in_path,
            out_path,
            auth,
        } => extra_cmd::run_key_unlock(&in_path, &out_path, auth),
        Command::Keyring { file_path, action } => extra_cmd::run_keyring(&file_path, action),
        Command::Stego { action } => extra_cmd::run_stego(action),
        Command::HiddenCreate {
            out_file,
            size,
            decoy_pass,
            decoy_in,
            hidden_pass,
            hidden_in,
            strength,
        } => extra_cmd::run_hidden_create(
            &out_file,
            size,
            decoy_pass.as_str(),
            &decoy_in,
            hidden_pass.as_str(),
            &hidden_in,
            strength,
        ),
        Command::HiddenOpen {
            in_file,
            out_file,
            pass,
            strength,
        } => extra_cmd::run_hidden_open(&in_file, &out_file, pass.as_str(), strength),
        Command::Send {
            addr,
            file_path,
            mode,
        } => extra_cmd::run_send(&addr, &file_path, mode),
        Command::Recv {
            listen_addr,
            out_dir,
            mode,
        } => extra_cmd::run_recv(&listen_addr, &out_dir, mode),
        Command::Ratchet {
            state_path,
            auth,
            action,
        } => extra_cmd::run_ratchet(&state_path, auth, action),
        Command::Inspect { path } => inspect_cmd::run_inspect(&path),
        Command::Shred { path, passes } => extra_cmd::run_shred(&path, passes),
        Command::Completions { shell } => extra_cmd::run_completions(&shell),
        Command::Keygen => keygen_cmd::run_keygen(),
        Command::HashText { text } => keygen_cmd::run_hash_text(&text),
        Command::HashFile { path } => keygen_cmd::run_hash_file(&path),
        Command::Bench => bench_cmd::run_bench(),
        Command::Audit => audit_cmd::run_audit(),
    }
}
