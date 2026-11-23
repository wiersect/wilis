//! Zero-dependency command-line interface for Wilis.

pub mod args;
pub mod audit_cmd;
pub mod bench_cmd;
pub mod file_cmd;
pub mod keygen_cmd;
pub mod text_cmd;

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
        Command::Keygen => keygen_cmd::run_keygen(),
        Command::HashText { text } => keygen_cmd::run_hash_text(&text),
        Command::HashFile { path } => keygen_cmd::run_hash_file(&path),
        Command::Bench => bench_cmd::run_bench(),
        Command::Audit => audit_cmd::run_audit(),
    }
}
