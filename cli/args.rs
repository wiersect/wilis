//! Command-line argument parser and help text definitions for Wilis v0.3.0.

use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfStrength;
use crate::sign::DEFAULT_TREE_HEIGHT;
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

/// Vault sub-actions.
#[derive(Debug)]
pub enum VaultAction {
    Init,
    Set { name: String, value: String },
    Get { name: String },
    List,
    Delete { name: String },
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
    EncryptDir {
        auth: AuthInput,
        aad: String,
        dir_path: String,
        output_file: String,
    },
    DecryptDir {
        auth: AuthInput,
        aad: String,
        input_file: String,
        out_dir: String,
    },
    Vault {
        vault_path: String,
        auth: AuthInput,
        action: VaultAction,
    },
    SignKeygen {
        out_prefix: String,
        height: u8,
    },
    SignFile {
        sk_path: String,
        input_path: String,
        sig_out_path: String,
    },
    VerifyFile {
        pk_path: String,
        input_path: String,
        sig_path: String,
    },
    SplitKey {
        secret_hex: String,
        total: u8,
        threshold: u8,
    },
    CombineKey {
        shares: Vec<String>,
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
Wilis v0.3.0 — Standalone Hardened Custom Cryptography Suite (WilisPerm-384)

USAGE:
  wilis <COMMAND> [OPTIONS]

ENCRYPTION & ARCHIVING:
  encrypt-text  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] <TEXT>
  decrypt-text  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] <BASE64>

  encrypt-file  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] --in <F> --out <F>
  decrypt-file  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] --in <F> --out <F>

  encrypt-dir   (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] --in <DIR> --out <FILE>
  decrypt-dir   (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] --in <FILE> --out <DIR>

ENCRYPTED SECRET VAULT:
  vault init    --file <VAULT.wils> (--pass <P> | --pass-prompt) [--keyfile <F>] [--strength S]
  vault set     --file <VAULT.wils> (--pass <P> | --pass-prompt) [--keyfile <F>] --name <KEY> --value <VAL>
  vault get     --file <VAULT.wils> (--pass <P> | --pass-prompt) [--keyfile <F>] --name <KEY>
  vault list    --file <VAULT.wils> (--pass <P> | --pass-prompt) [--keyfile <F>]
  vault del     --file <VAULT.wils> (--pass <P> | --pass-prompt) [--keyfile <F>] --name <KEY>

POST-QUANTUM DIGITAL SIGNATURES (WilisSign — WOTS+ Merkle Tree):
  sign-keygen   --out <PREFIX> [--height 2..10]   (writes <PREFIX>.wsk and <PREFIX>.wpk)
  sign          --sk <KEY.wsk> --in <FILE> --out <FILE.wsig>
  verify        --pk <KEY.wpk> --in <FILE> --sig <FILE.wsig>

SHAMIR SECRET SHARING (WilisSplit — GF(2^8)):
  split-key     --secret <HEX> --total <N> --threshold <K>
  combine-key   <SHARE_1> <SHARE_2> [...]

UTILITIES & CRYPTANALYSIS:
  keygen        Generate a fresh 256-bit random hex key & WilisHash-256 Key ID.
  hash          (--file <FILE> | <TEXT>)
  bench         Run bijectivity, avalanche, and AEAD throughput benchmarks.
  audit         Run full scientific cryptanalysis (SAC, BIC, DDT/LAT, NIST randomness).
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
        "encrypt-file" => parse_io_cmd(&args[1..], IoMode::EncryptFile),
        "decrypt-file" => parse_io_cmd(&args[1..], IoMode::DecryptFile),
        "encrypt-dir" => parse_io_cmd(&args[1..], IoMode::EncryptDir),
        "decrypt-dir" => parse_io_cmd(&args[1..], IoMode::DecryptDir),
        "vault" => parse_vault_cmd(&args[1..]),
        "sign-keygen" => parse_sign_keygen(&args[1..]),
        "sign" => parse_sign_cmd(&args[1..]),
        "verify" => parse_verify_cmd(&args[1..]),
        "split-key" => parse_split_key(&args[1..]),
        "combine-key" => parse_combine_key(&args[1..]),
        "hash" => parse_hash_cmd(&args[1..]),
        unknown => Err(WilisError::CliUsage(format!(
            "unknown command '{unknown}'. Run 'wilis help' for usage."
        ))),
    }
}

enum IoMode {
    EncryptFile,
    DecryptFile,
    EncryptDir,
    DecryptDir,
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
                pass = Some(req_val(args, i, "--pass")?);
            }
            "--pass-prompt" => pass_prompt = true,
            "--key" => {
                i += 1;
                raw_key = Some(parse_raw_key(&req_val(args, i, "--key")?)?);
            }
            "--keyfile" => {
                i += 1;
                keyfile = Some(req_val(args, i, "--keyfile")?);
            }
            "--strength" => {
                i += 1;
                strength = KdfStrength::from_name(&req_val(args, i, "--strength")?)?;
            }
            "--aad" => {
                i += 1;
                aad = req_val(args, i, "--aad")?;
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

fn parse_io_cmd(args: &[String], mode: IoMode) -> Result<Command> {
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
                pass = Some(req_val(args, i, "--pass")?);
            }
            "--pass-prompt" => pass_prompt = true,
            "--key" => {
                i += 1;
                raw_key = Some(parse_raw_key(&req_val(args, i, "--key")?)?);
            }
            "--keyfile" => {
                i += 1;
                keyfile = Some(req_val(args, i, "--keyfile")?);
            }
            "--strength" => {
                i += 1;
                strength = KdfStrength::from_name(&req_val(args, i, "--strength")?)?;
            }
            "--aad" => {
                i += 1;
                aad = req_val(args, i, "--aad")?;
            }
            "--in" => {
                i += 1;
                input_path = Some(req_val(args, i, "--in")?);
            }
            "--out" => {
                i += 1;
                output_path = Some(req_val(args, i, "--out")?);
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown argument '{other}'")));
            }
        }
        i += 1;
    }

    let input_path =
        input_path.ok_or_else(|| WilisError::CliUsage("missing required --in <PATH>".into()))?;
    let output_path =
        output_path.ok_or_else(|| WilisError::CliUsage("missing required --out <PATH>".into()))?;

    let is_encrypt = matches!(mode, IoMode::EncryptFile | IoMode::EncryptDir);
    let auth = resolve_auth(pass, pass_prompt, raw_key, keyfile, strength, is_encrypt)?;

    Ok(match mode {
        IoMode::EncryptFile => Command::EncryptFile {
            auth,
            aad,
            input_path,
            output_path,
        },
        IoMode::DecryptFile => Command::DecryptFile {
            auth,
            aad,
            input_path,
            output_path,
        },
        IoMode::EncryptDir => Command::EncryptDir {
            auth,
            aad,
            dir_path: input_path,
            output_file: output_path,
        },
        IoMode::DecryptDir => Command::DecryptDir {
            auth,
            aad,
            input_file: input_path,
            out_dir: output_path,
        },
    })
}

fn parse_vault_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "vault requires a subcommand: init, set, get, list, del".into(),
        ));
    }
    let sub = args[0].as_str();
    let mut vault_file: Option<String> = None;
    let mut pass: Option<String> = None;
    let mut pass_prompt = false;
    let mut keyfile: Option<String> = None;
    let mut strength = KdfStrength::Interactive;
    let mut name: Option<String> = None;
    let mut value: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                vault_file = Some(req_val(args, i, "--file")?);
            }
            "--pass" => {
                i += 1;
                pass = Some(req_val(args, i, "--pass")?);
            }
            "--pass-prompt" => pass_prompt = true,
            "--keyfile" => {
                i += 1;
                keyfile = Some(req_val(args, i, "--keyfile")?);
            }
            "--strength" => {
                i += 1;
                strength = KdfStrength::from_name(&req_val(args, i, "--strength")?)?;
            }
            "--name" => {
                i += 1;
                name = Some(req_val(args, i, "--name")?);
            }
            "--value" => {
                i += 1;
                value = Some(req_val(args, i, "--value")?);
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown vault option '{other}'")));
            }
        }
        i += 1;
    }

    let vault_path =
        vault_file.ok_or_else(|| WilisError::CliUsage("missing required --file <VAULT.wils>".into()))?;
    let action = match sub {
        "init" => VaultAction::Init,
        "set" => VaultAction::Set {
            name: name.ok_or_else(|| WilisError::CliUsage("vault set requires --name <KEY>".into()))?,
            value: value.ok_or_else(|| WilisError::CliUsage("vault set requires --value <VAL>".into()))?,
        },
        "get" => VaultAction::Get {
            name: name.ok_or_else(|| WilisError::CliUsage("vault get requires --name <KEY>".into()))?,
        },
        "list" => VaultAction::List,
        "del" | "delete" | "rm" => VaultAction::Delete {
            name: name.ok_or_else(|| WilisError::CliUsage("vault del requires --name <KEY>".into()))?,
        },
        other => {
            return Err(WilisError::CliUsage(format!(
                "unknown vault subcommand '{other}' (expected: init, set, get, list, del)"
            )));
        }
    };

    let confirm_pass = matches!(action, VaultAction::Init);
    let auth = resolve_auth(pass, pass_prompt, None, keyfile, strength, confirm_pass)?;
    Ok(Command::Vault {
        vault_path,
        auth,
        action,
    })
}

fn parse_sign_keygen(args: &[String]) -> Result<Command> {
    let mut out_prefix: Option<String> = None;
    let mut height = DEFAULT_TREE_HEIGHT;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_prefix = Some(req_val(args, i, "--out")?);
            }
            "--height" => {
                i += 1;
                let s = req_val(args, i, "--height")?;
                height = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --height '{s}' (expected integer 2..10)"))
                })?;
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
            }
        }
        i += 1;
    }
    let out_prefix =
        out_prefix.ok_or_else(|| WilisError::CliUsage("sign-keygen requires --out <PREFIX>".into()))?;
    Ok(Command::SignKeygen { out_prefix, height })
}

fn parse_sign_cmd(args: &[String]) -> Result<Command> {
    let mut sk: Option<String> = None;
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sk" => {
                i += 1;
                sk = Some(req_val(args, i, "--sk")?);
            }
            "--in" => {
                i += 1;
                input = Some(req_val(args, i, "--in")?);
            }
            "--out" => {
                i += 1;
                out = Some(req_val(args, i, "--out")?);
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::SignFile {
        sk_path: sk.ok_or_else(|| WilisError::CliUsage("sign requires --sk <KEY.wsk>".into()))?,
        input_path: input.ok_or_else(|| WilisError::CliUsage("sign requires --in <FILE>".into()))?,
        sig_out_path: out
            .ok_or_else(|| WilisError::CliUsage("sign requires --out <FILE.wsig>".into()))?,
    })
}

fn parse_verify_cmd(args: &[String]) -> Result<Command> {
    let mut pk: Option<String> = None;
    let mut input: Option<String> = None;
    let mut sig: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pk" => {
                i += 1;
                pk = Some(req_val(args, i, "--pk")?);
            }
            "--in" => {
                i += 1;
                input = Some(req_val(args, i, "--in")?);
            }
            "--sig" => {
                i += 1;
                sig = Some(req_val(args, i, "--sig")?);
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::VerifyFile {
        pk_path: pk.ok_or_else(|| WilisError::CliUsage("verify requires --pk <KEY.wpk>".into()))?,
        input_path: input
            .ok_or_else(|| WilisError::CliUsage("verify requires --in <FILE>".into()))?,
        sig_path: sig
            .ok_or_else(|| WilisError::CliUsage("verify requires --sig <FILE.wsig>".into()))?,
    })
}

fn parse_split_key(args: &[String]) -> Result<Command> {
    let mut secret_hex: Option<String> = None;
    let mut total: Option<u8> = None;
    let mut threshold: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                i += 1;
                secret_hex = Some(req_val(args, i, "--secret")?);
            }
            "--total" | "-n" => {
                i += 1;
                let s = req_val(args, i, "--total")?;
                total = Some(s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --total '{s}' (expected 2..=255)"))
                })?);
            }
            "--threshold" | "-k" => {
                i += 1;
                let s = req_val(args, i, "--threshold")?;
                threshold = Some(s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --threshold '{s}' (expected 2..=255)"))
                })?);
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::SplitKey {
        secret_hex: secret_hex
            .ok_or_else(|| WilisError::CliUsage("split-key requires --secret <HEX>".into()))?,
        total: total.ok_or_else(|| WilisError::CliUsage("split-key requires --total <N>".into()))?,
        threshold: threshold
            .ok_or_else(|| WilisError::CliUsage("split-key requires --threshold <K>".into()))?,
    })
}

fn parse_combine_key(args: &[String]) -> Result<Command> {
    if args.len() < 2 {
        return Err(WilisError::CliUsage(
            "combine-key requires at least 2 share tokens".into(),
        ));
    }
    Ok(Command::CombineKey {
        shares: args.to_vec(),
    })
}

fn parse_hash_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "hash requires either --file <FILE> or <TEXT>".into(),
        ));
    }
    if args[0] == "--file" {
        let path = req_val(args, 1, "--file")?;
        Ok(Command::HashFile { path })
    } else {
        Ok(Command::HashText {
            text: args[0].clone(),
        })
    }
}

fn req_val(args: &[String], idx: usize, flag: &str) -> Result<String> {
    args.get(idx)
        .cloned()
        .ok_or_else(|| WilisError::CliUsage(format!("missing value for {flag}")))
}
