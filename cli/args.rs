//! Command-line argument parser and help text definitions.

use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfStrength;
use crate::utils::hex::decode_hex;
use crate::utils::prompt::{hash_keyfile, read_hidden_passphrase};
use crate::utils::zeroize::SecretKey;

/// Authentication credential supplied on the command line (or via hidden prompt).
#[derive(Debug)]
pub enum AuthInput {
    Passphrase {
        passphrase: String,
        keyfile_hash: Option<[u8; HASH_BYTES]>,
        strength: KdfStrength,
    },
    RawKey(SecretKey),
}

/// Parsed CLI subcommands.
#[derive(Debug)]
pub enum Command {
    Help,
    EncryptText {
        auth: AuthInput,
        aad: String,
        plaintext: String,
    },
    DecryptText {
        auth: AuthInput,
        aad: String,
        ciphertext_b64: String,
    },
    EncryptFile {
        auth: AuthInput,
        aad: String,
        input_path: String,
        output_path: String,
    },
    DecryptFile {
        auth: AuthInput,
        aad: String,
        input_path: String,
        output_path: String,
    },
    Keygen,
    HashText {
        text: String,
    },
    HashFile {
        path: String,
    },
    Bench,
    Audit,
}

/// Returns formatted CLI usage documentation.
pub fn usage_text() -> &'static str {
    "\
Wilis v0.2.0 — Standalone Hardened Custom Cryptography Suite (WilisPerm-384)

USAGE:
  wilis <COMMAND> [OPTIONS]

COMMANDS:
  encrypt-text  (--pass <PASS> | --pass-prompt | --key <64-HEX>) [--keyfile <FILE>]
                [--strength interactive|high|paranoid] [--aad <TEXT>] <PLAINTEXT>
                Encrypt UTF-8 text into a Base64-encoded WILS container.

  decrypt-text  (--pass <PASS> | --pass-prompt | --key <64-HEX>) [--keyfile <FILE>]
                [--aad <TEXT>] <BASE64>
                Verify and decrypt a Base64-encoded WILS container back to UTF-8.

  encrypt-file  (--pass <PASS> | --pass-prompt | --key <64-HEX>) [--keyfile <FILE>]
                [--strength interactive|high|paranoid] [--aad <TEXT>] --in <FILE> --out <FILE>
                Stream-encrypt any file (constant-memory WILS v2 chunks).

  decrypt-file  (--pass <PASS> | --pass-prompt | --key <64-HEX>) [--keyfile <FILE>]
                [--aad <TEXT>] --in <FILE> --out <FILE>
                Authenticate and stream-decrypt a WILS v1 or v2 file.

  keygen        Generate a fresh 256-bit random key (hex) and its WilisHash-256 ID.

  hash          (--file <FILE> | <TEXT>)
                Compute the 256-bit WilisHash-256 digest of text or a file.

  bench         Run live bijectivity, avalanche effect, and AEAD throughput benchmarks.

  audit         Run full scientific cryptanalysis (round-by-round SAC, BIC, DDT/LAT,
                and NIST-style keystream randomness battery).

  help          Display this usage guide."
}

/// Parses command-line arguments (excluding program name `argv[0]`).
pub fn parse_args(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Ok(Command::Help);
    }

    match args[0].as_str() {
        "help" | "-h" | "--help" => Ok(Command::Help),
        "keygen" => Ok(Command::Keygen),
        "bench" => Ok(Command::Bench),
        "audit" => Ok(Command::Audit),
        "encrypt-text" => parse_text_cmd(&args[1..], true),
        "decrypt-text" => parse_text_cmd(&args[1..], false),
        "encrypt-file" => parse_file_cmd(&args[1..], true),
        "decrypt-file" => parse_file_cmd(&args[1..], false),
        "hash" => parse_hash_cmd(&args[1..]),
        unknown => Err(WilisError::CliUsage(format!(
            "unknown command '{unknown}'. Run 'wilis help' for usage."
        ))),
    }
}

fn parse_raw_key(hex_str: &str) -> Result<SecretKey> {
    let bytes = decode_hex(hex_str)?;
    if bytes.len() != KEY_BYTES {
        return Err(WilisError::InvalidKey(format!(
            "expected {} hex chars ({} bytes), got {} bytes",
            KEY_BYTES * 2,
            KEY_BYTES,
            bytes.len()
        )));
    }
    let arr: [u8; KEY_BYTES] = bytes.try_into().expect("32-byte key");
    Ok(SecretKey::from_bytes(arr))
}

fn resolve_auth(
    pass: Option<String>,
    pass_prompt: bool,
    raw_key: Option<SecretKey>,
    keyfile_path: Option<String>,
    strength: KdfStrength,
    is_encrypt: bool,
) -> Result<AuthInput> {
    if let Some(key) = raw_key {
        if pass.is_some() || pass_prompt {
            return Err(WilisError::CliUsage(
                "cannot combine --key with --pass or --pass-prompt".into(),
            ));
        }
        if keyfile_path.is_some() {
            return Err(WilisError::CliUsage(
                "--keyfile is only used with passphrase mode (--pass / --pass-prompt)".into(),
            ));
        }
        return Ok(AuthInput::RawKey(key));
    }

    let passphrase = if pass_prompt {
        read_hidden_passphrase("Enter passphrase: ", is_encrypt)?
    } else if let Some(p) = pass {
        p
    } else {
        return Err(WilisError::CliUsage(
            "must specify --pass <PASS>, --pass-prompt, or --key <64-HEX>".into(),
        ));
    };

    let keyfile_hash = match keyfile_path {
        Some(path) => Some(hash_keyfile(&path)?),
        None => None,
    };

    Ok(AuthInput::Passphrase {
        passphrase,
        keyfile_hash,
        strength,
    })
}

fn parse_text_cmd(args: &[String], encrypt: bool) -> Result<Command> {
    let mut pass: Option<String> = None;
    let mut pass_prompt = false;
    let mut raw_key: Option<SecretKey> = None;
    let mut keyfile: Option<String> = None;
    let mut strength = KdfStrength::Interactive;
    let mut aad = String::new();
    let mut positional: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pass" => {
                i += 1;
                pass = Some(
                    args.get(i)
                        .ok_or_else(|| WilisError::CliUsage("missing value for --pass".into()))?
                        .clone(),
                );
            }
            "--pass-prompt" => {
                pass_prompt = true;
            }
            "--key" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| WilisError::CliUsage("missing value for --key".into()))?;
                raw_key = Some(parse_raw_key(val)?);
            }
            "--keyfile" => {
                i += 1;
                keyfile = Some(
                    args.get(i)
                        .ok_or_else(|| WilisError::CliUsage("missing path for --keyfile".into()))?
                        .clone(),
                );
            }
            "--strength" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| WilisError::CliUsage("missing value for --strength".into()))?;
                strength = KdfStrength::from_name(val)?;
            }
            "--aad" => {
                i += 1;
                aad = args
                    .get(i)
                    .ok_or_else(|| WilisError::CliUsage("missing value for --aad".into()))?
                    .clone();
            }
            other if other.starts_with("--") => {
                return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
            }
            other => {
                if positional.is_some() {
                    return Err(WilisError::CliUsage(
                        "unexpected extra positional argument".into(),
                    ));
                }
                positional = Some(other.to_string());
            }
        }
        i += 1;
    }

    let payload = positional.ok_or_else(|| {
        WilisError::CliUsage(if encrypt {
            "missing <PLAINTEXT> argument".into()
        } else {
            "missing <BASE64> ciphertext argument".into()
        })
    })?;

    let auth = resolve_auth(pass, pass_prompt, raw_key, keyfile, strength, encrypt)?;

    if encrypt {
        Ok(Command::EncryptText {
            auth,
            aad,
            plaintext: payload,
        })
    } else {
        Ok(Command::DecryptText {
            auth,
            aad,
            ciphertext_b64: payload,
        })
    }
}

fn parse_file_cmd(args: &[String], encrypt: bool) -> Result<Command> {
    let mut pass: Option<String> = None;
    let mut pass_prompt = false;
    let mut raw_key: Option<SecretKey> = None;
    let mut keyfile: Option<String> = None;
    let mut strength = KdfStrength::Interactive;
    let mut aad = String::new();
    let mut input_path: Option<String> = None;
    let mut output_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pass" => {
                i += 1;
                pass = Some(
                    args.get(i)
                        .ok_or_else(|| WilisError::CliUsage("missing value for --pass".into()))?
                        .clone(),
                );
            }
            "--pass-prompt" => {
                pass_prompt = true;
            }
            "--key" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| WilisError::CliUsage("missing value for --key".into()))?;
                raw_key = Some(parse_raw_key(val)?);
            }
            "--keyfile" => {
                i += 1;
                keyfile = Some(
                    args.get(i)
                        .ok_or_else(|| WilisError::CliUsage("missing path for --keyfile".into()))?
                        .clone(),
                );
            }
            "--strength" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| WilisError::CliUsage("missing value for --strength".into()))?;
                strength = KdfStrength::from_name(val)?;
            }
            "--aad" => {
                i += 1;
                aad = args
                    .get(i)
                    .ok_or_else(|| WilisError::CliUsage("missing value for --aad".into()))?
                    .clone();
            }
            "--in" => {
                i += 1;
                input_path = Some(
                    args.get(i)
                        .ok_or_else(|| WilisError::CliUsage("missing value for --in".into()))?
                        .clone(),
                );
            }
            "--out" => {
                i += 1;
                output_path = Some(
                    args.get(i)
                        .ok_or_else(|| WilisError::CliUsage("missing value for --out".into()))?
                        .clone(),
                );
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown argument '{other}'")));
            }
        }
        i += 1;
    }

    let input_path =
        input_path.ok_or_else(|| WilisError::CliUsage("missing required --in <FILE>".into()))?;
    let output_path = output_path
        .ok_or_else(|| WilisError::CliUsage("missing required --out <FILE>".into()))?;

    let auth = resolve_auth(pass, pass_prompt, raw_key, keyfile, strength, encrypt)?;

    if encrypt {
        Ok(Command::EncryptFile {
            auth,
            aad,
            input_path,
            output_path,
        })
    } else {
        Ok(Command::DecryptFile {
            auth,
            aad,
            input_path,
            output_path,
        })
    }
}

fn parse_hash_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "hash requires either --file <FILE> or <TEXT>".into(),
        ));
    }
    if args[0] == "--file" {
        let path = args
            .get(1)
            .ok_or_else(|| WilisError::CliUsage("missing path for --file".into()))?;
        Ok(Command::HashFile { path: path.clone() })
    } else {
        Ok(Command::HashText {
            text: args[0].clone(),
        })
    }
}
