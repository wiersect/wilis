//! Command-line argument parser and help text definitions for Wilis v0.4.5.

use std::path::Path;

use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfStrength;
use crate::sign::DEFAULT_TREE_HEIGHT;
use crate::utils::hex::decode_hex;
use crate::utils::prompt::{hash_keyfile, read_hidden_passphrase};
use crate::utils::zeroize::{paths_refer_to_same_file, zeroize_bytes, SecretKey};

/// Authentication credential supplied on the command line (auto-zeroizes passphrase on drop).
#[derive(Debug)]
pub enum AuthInput {
    Passphrase {
        passphrase: String,
        keyfile_hash: Option<[u8; HASH_BYTES]>,
        strength: KdfStrength,
    },
    RawKey(SecretKey),
}

impl Drop for AuthInput {
    fn drop(&mut self) {
        if let AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } = self
        {
            // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
            let bytes = unsafe { passphrase.as_bytes_mut() };
            zeroize_bytes(bytes);
            if let Some(kf) = keyfile_hash {
                zeroize_bytes(kf);
            }
        }
    }
}

/// Vault sub-actions (auto-zeroizes secret values on drop).
#[derive(Debug)]
pub enum VaultAction {
    Init,
    Set { name: String, value: String },
    Get { name: String },
    List,
    Delete { name: String },
}

impl Drop for VaultAction {
    fn drop(&mut self) {
        if let VaultAction::Set { value, .. } = self {
            // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
            zeroize_bytes(unsafe { value.as_bytes_mut() });
        }
    }
}

/// Internal RAII wrapper ensuring parsed CLI secrets are always volatile-zeroized on early `?` returns.
struct ZeroizeStr(String);

impl ZeroizeStr {
    fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for ZeroizeStr {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
}

fn zeroize_string(s: &mut String) {
    // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { s.as_bytes_mut() });
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
    KemKeygen {
        out_prefix: String,
    },
    PubEncrypt {
        pk_path: String,
        aad: String,
        input_path: String,
        output_path: String,
    },
    PubDecrypt {
        sk_path: String,
        aad: String,
        input_path: String,
        output_path: String,
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
    Mac {
        key: SecretKey,
        file_path: Option<String>,
        text: Option<String>,
    },
    MacVerify {
        key: SecretKey,
        tag_hex: String,
        file_path: Option<String>,
        text: Option<String>,
    },
    Rand {
        bytes: usize,
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
pub fn usage_text() -> String {
    format!(
        "\
Wilis v{} — Standalone Post-Quantum & Symmetric Cryptography Suite (WilisPerm-384)

USAGE:
  wilis <COMMAND> [OPTIONS]

SYMMETRIC ENCRYPTION & ARCHIVING:
  encrypt-text  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] <TEXT>
  decrypt-text  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] <BASE64>
  encrypt-file  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] --in <F> --out <F>
  decrypt-file  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] --in <F> --out <F>
  encrypt-dir   (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] --in <DIR> --out <F>
  decrypt-dir   (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] --in <F> --out <DIR>

POST-QUANTUM PUBLIC-KEY ENCRYPTION (WilisKEM — Module-LWE 768 IND-CCA2):
  kem-keygen    --out <PREFIX>                    (writes <PREFIX>.wkp public & <PREFIX>.wks secret)
  pub-encrypt   --pk <KEY.wkp> [--aad <T>] --in <FILE> --out <FILE.wpke>
  pub-decrypt   --sk <KEY.wks> [--aad <T>] --in <FILE.wpke> --out <FILE>

POST-QUANTUM DIGITAL SIGNATURES (WilisSign — WOTS+ Merkle Tree):
  sign-keygen   --out <PREFIX> [--height 2..10]   (writes <PREFIX>.wsk and <PREFIX>.wpk)
  sign          --sk <KEY.wsk> --in <FILE> --out <FILE.wsig>
  verify        --pk <KEY.wpk> --in <FILE> --sig <FILE.wsig>

ENCRYPTED SECRET VAULT & SHAMIR SECRET SHARING:
  vault         (init|set|get|list|del) --file <VAULT.wils> (--pass <P> | --pass-prompt) [--keyfile <F>] [--name K --value V]
  split-key     --secret <HEX> --total <N> --threshold <K>
  combine-key   <SHARE_1> <SHARE_2> [...]

MAC, HASH, RANDOM & CRYPTANALYSIS:
  mac           --key <64-HEX> (--file <FILE> | <TEXT>)
  mac-verify    --key <64-HEX> --tag <64-HEX> (--file <FILE> | <TEXT>)
  hash          (--file <FILE> | <TEXT>)
  keygen        Generate a fresh 256-bit random hex key & WilisHash-256 Key ID.
  rand          --bytes <N>                       Generate N cryptographically secure random bytes (hex).
  bench         Run bijectivity, avalanche, and AEAD throughput benchmarks.
  audit         Run 6-part scientific cryptanalysis (SAC, BIC, DDT/LAT, NIST, Related-Key, KEM CCA2).
  help          Display this usage guide.",
        env!("CARGO_PKG_VERSION")
    )
}

/// Parses command-line arguments (excluding program name `argv[0]`).
pub fn parse_args(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Ok(Command::Help);
    }

    match args[0].as_str() {
        "help" | "-h" | "--help" => Ok(Command::Help),
        "keygen" => ensure_no_extra_args("keygen", &args[1..]).map(|()| Command::Keygen),
        "bench" => ensure_no_extra_args("bench", &args[1..]).map(|()| Command::Bench),
        "audit" => ensure_no_extra_args("audit", &args[1..]).map(|()| Command::Audit),
        "encrypt-text" => parse_text_cmd(&args[1..], true),
        "decrypt-text" => parse_text_cmd(&args[1..], false),
        "encrypt-file" => parse_io_cmd(&args[1..], IoMode::EncryptFile),
        "decrypt-file" => parse_io_cmd(&args[1..], IoMode::DecryptFile),
        "encrypt-dir" => parse_io_cmd(&args[1..], IoMode::EncryptDir),
        "decrypt-dir" => parse_io_cmd(&args[1..], IoMode::DecryptDir),
        "kem-keygen" => parse_kem_keygen(&args[1..]),
        "pub-encrypt" => parse_pub_enc(&args[1..]),
        "pub-decrypt" => parse_pub_dec(&args[1..]),
        "vault" => parse_vault_cmd(&args[1..]),
        "sign-keygen" => parse_sign_keygen(&args[1..]),
        "sign" => parse_sign_cmd(&args[1..]),
        "verify" => parse_verify_cmd(&args[1..]),
        "split-key" => parse_split_key(&args[1..]),
        "combine-key" => parse_combine_key(&args[1..]),
        "mac" => parse_mac_cmd(&args[1..], false),
        "mac-verify" => parse_mac_cmd(&args[1..], true),
        "rand" => parse_rand_cmd(&args[1..]),
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

fn ensure_no_extra_args(cmd: &str, rest: &[String]) -> Result<()> {
    if let Some(extra) = rest.first() {
        return Err(WilisError::CliUsage(format!(
            "unexpected argument '{extra}' for command '{cmd}'"
        )));
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, val: T, flag: &str) -> Result<()> {
    if slot.is_some() {
        return Err(WilisError::CliUsage(format!("duplicate option '{flag}'")));
    }
    *slot = Some(val);
    Ok(())
}

fn parse_raw_key(hex_str: &str) -> Result<SecretKey> {
    let mut bytes = decode_hex(hex_str)?;
    if bytes.len() != KEY_BYTES {
        let len = bytes.len();
        zeroize_bytes(&mut bytes);
        return Err(WilisError::InvalidKey(format!(
            "expected {} hex chars ({} bytes), got {} bytes",
            KEY_BYTES * 2,
            KEY_BYTES,
            len
        )));
    }
    let mut arr = [0u8; KEY_BYTES];
    arr.copy_from_slice(&bytes);
    zeroize_bytes(&mut bytes);
    let sk = SecretKey::from_bytes(arr);
    zeroize_bytes(&mut arr);
    Ok(sk)
}

fn resolve_auth(
    pass: Option<ZeroizeStr>,
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

    if pass.is_some() && pass_prompt {
        return Err(WilisError::CliUsage(
            "cannot combine --pass with --pass-prompt".into(),
        ));
    }

    let mut passphrase = if pass_prompt {
        read_hidden_passphrase("Enter passphrase: ", is_encrypt)?
    } else if let Some(p) = pass {
        let s = p.into_inner();
        if s.is_empty() {
            return Err(WilisError::InvalidKey(
                "passphrase must not be empty".into(),
            ));
        }
        s
    } else {
        return Err(WilisError::CliUsage(
            "must specify --pass <PASS>, --pass-prompt, or --key <64-HEX>".into(),
        ));
    };

    let keyfile_hash = match keyfile_path {
        Some(path) => match hash_keyfile(&path) {
            Ok(h) => Some(h),
            Err(e) => {
                zeroize_string(&mut passphrase);
                return Err(e);
            }
        },
        None => None,
    };

    Ok(AuthInput::Passphrase {
        passphrase,
        keyfile_hash,
        strength,
    })
}

fn parse_text_cmd(args: &[String], encrypt: bool) -> Result<Command> {
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut raw_key: Option<SecretKey> = None;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut aad: Option<String> = None;
    let mut positional: Option<String> = None;

    let mut i = 0;
    let mut end_of_opts = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if !end_of_opts {
            match arg {
                "--" => {
                    end_of_opts = true;
                    i += 1;
                    continue;
                }
                "--pass" => {
                    i += 1;
                    set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
                    i += 1;
                    continue;
                }
                "--pass-prompt" => {
                    if pass_prompt {
                        return Err(WilisError::CliUsage("duplicate option '--pass-prompt'".into()));
                    }
                    pass_prompt = true;
                    i += 1;
                    continue;
                }
                "--key" => {
                    i += 1;
                    set_once(&mut raw_key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
                    i += 1;
                    continue;
                }
                "--keyfile" => {
                    i += 1;
                    set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
                    i += 1;
                    continue;
                }
                "--strength" => {
                    i += 1;
                    set_once(
                        &mut strength,
                        KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                        "--strength",
                    )?;
                    i += 1;
                    continue;
                }
                "--aad" => {
                    i += 1;
                    set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
                    i += 1;
                    continue;
                }
                other if other.starts_with("--") => {
                    return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
                }
                _ => {}
            }
        }
        if positional.is_some() {
            return Err(WilisError::CliUsage(
                "unexpected extra positional argument".into(),
            ));
        }
        positional = Some(arg.to_string());
        i += 1;
    }

    let payload = positional.ok_or_else(|| {
        WilisError::CliUsage(if encrypt {
            "missing <PLAINTEXT> argument".into()
        } else {
            "missing <BASE64> ciphertext argument".into()
        })
    })?;

    let auth = resolve_auth(
        pass,
        pass_prompt,
        raw_key,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        encrypt,
    )?;
    let aad = aad.unwrap_or_default();
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
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut raw_key: Option<SecretKey> = None;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut aad: Option<String> = None;
    let mut input_path: Option<String> = None;
    let mut output_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--pass-prompt" => {
                if pass_prompt {
                    return Err(WilisError::CliUsage("duplicate option '--pass-prompt'".into()));
                }
                pass_prompt = true;
            }
            "--key" => {
                i += 1;
                set_once(&mut raw_key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
            }
            "--keyfile" => {
                i += 1;
                set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input_path, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut output_path, req_val(args, i, "--out")?, "--out")?;
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

    if let Some(ref kf) = keyfile {
        if paths_refer_to_same_file(Path::new(kf), Path::new(&output_path)) {
            return Err(WilisError::InvalidParameters(
                "output path must not overwrite the 2FA keyfile".into(),
            ));
        }
    }

    let is_encrypt = matches!(mode, IoMode::EncryptFile | IoMode::EncryptDir);
    let auth = resolve_auth(
        pass,
        pass_prompt,
        raw_key,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        is_encrypt,
    )?;
    let aad = aad.unwrap_or_default();

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

fn parse_kem_keygen(args: &[String]) -> Result<Command> {
    let mut out_prefix: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                set_once(&mut out_prefix, req_val(args, i, "--out")?, "--out")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::KemKeygen {
        out_prefix: out_prefix
            .ok_or_else(|| WilisError::CliUsage("kem-keygen requires --out <PREFIX>".into()))?,
    })
}

fn parse_pub_enc(args: &[String]) -> Result<Command> {
    let mut pk: Option<String> = None;
    let mut aad: Option<String> = None;
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pk" => {
                i += 1;
                set_once(&mut pk, req_val(args, i, "--pk")?, "--pk")?;
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out, req_val(args, i, "--out")?, "--out")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::PubEncrypt {
        pk_path: pk.ok_or_else(|| WilisError::CliUsage("pub-encrypt requires --pk <KEY.wkp>".into()))?,
        aad: aad.unwrap_or_default(),
        input_path: input.ok_or_else(|| WilisError::CliUsage("pub-encrypt requires --in <FILE>".into()))?,
        output_path: out.ok_or_else(|| WilisError::CliUsage("pub-encrypt requires --out <FILE>".into()))?,
    })
}

fn parse_pub_dec(args: &[String]) -> Result<Command> {
    let mut sk: Option<String> = None;
    let mut aad: Option<String> = None;
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sk" => {
                i += 1;
                set_once(&mut sk, req_val(args, i, "--sk")?, "--sk")?;
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out, req_val(args, i, "--out")?, "--out")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::PubDecrypt {
        sk_path: sk.ok_or_else(|| WilisError::CliUsage("pub-decrypt requires --sk <KEY.wks>".into()))?,
        aad: aad.unwrap_or_default(),
        input_path: input.ok_or_else(|| WilisError::CliUsage("pub-decrypt requires --in <FILE>".into()))?,
        output_path: out.ok_or_else(|| WilisError::CliUsage("pub-decrypt requires --out <FILE>".into()))?,
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
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut name: Option<String> = None;
    let mut value: Option<ZeroizeStr> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                set_once(&mut vault_file, req_val(args, i, "--file")?, "--file")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--pass-prompt" => {
                if pass_prompt {
                    return Err(WilisError::CliUsage("duplicate option '--pass-prompt'".into()));
                }
                pass_prompt = true;
            }
            "--keyfile" => {
                i += 1;
                set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            "--name" => {
                i += 1;
                set_once(&mut name, req_val(args, i, "--name")?, "--name")?;
            }
            "--value" => {
                i += 1;
                set_once(&mut value, ZeroizeStr(req_val(args, i, "--value")?), "--value")?;
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown vault option '{other}'")));
            }
        }
        i += 1;
    }

    let vault_path = vault_file
        .ok_or_else(|| WilisError::CliUsage("missing required --file <VAULT.wils>".into()))?;
    if let Some(ref kf) = keyfile {
        if paths_refer_to_same_file(Path::new(kf), Path::new(&vault_path)) {
            return Err(WilisError::InvalidParameters(
                "vault file path must not overwrite the 2FA keyfile".into(),
            ));
        }
    }
    let action = match sub {
        "init" => {
            if name.is_some() || value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault init does not accept --name or --value".into(),
                ));
            }
            VaultAction::Init
        }
        "set" => VaultAction::Set {
            name: name.ok_or_else(|| WilisError::CliUsage("vault set requires --name <KEY>".into()))?,
            value: value
                .ok_or_else(|| WilisError::CliUsage("vault set requires --value <VAL>".into()))?
                .into_inner(),
        },
        "get" => {
            if value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault get does not accept --value".into(),
                ));
            }
            VaultAction::Get {
                name: name.ok_or_else(|| WilisError::CliUsage("vault get requires --name <KEY>".into()))?,
            }
        }
        "list" => {
            if name.is_some() || value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault list does not accept --name or --value".into(),
                ));
            }
            VaultAction::List
        }
        "del" | "delete" | "rm" => {
            if value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault del does not accept --value".into(),
                ));
            }
            VaultAction::Delete {
                name: name.ok_or_else(|| WilisError::CliUsage("vault del requires --name <KEY>".into()))?,
            }
        }
        other => {
            return Err(WilisError::CliUsage(format!(
                "unknown vault subcommand '{other}' (expected: init, set, get, list, del)"
            )));
        }
    };

    let confirm_pass = matches!(action, VaultAction::Init);
    let auth = resolve_auth(
        pass,
        pass_prompt,
        None,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        confirm_pass,
    )?;
    Ok(Command::Vault {
        vault_path,
        auth,
        action,
    })
}

fn parse_sign_keygen(args: &[String]) -> Result<Command> {
    let mut out_prefix: Option<String> = None;
    let mut height: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                set_once(&mut out_prefix, req_val(args, i, "--out")?, "--out")?;
            }
            "--height" => {
                i += 1;
                let s = req_val(args, i, "--height")?;
                let h = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --height '{s}' (expected integer 2..10)"))
                })?;
                set_once(&mut height, h, "--height")?;
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
            }
        }
        i += 1;
    }
    let out_prefix =
        out_prefix.ok_or_else(|| WilisError::CliUsage("sign-keygen requires --out <PREFIX>".into()))?;
    Ok(Command::SignKeygen {
        out_prefix,
        height: height.unwrap_or(DEFAULT_TREE_HEIGHT),
    })
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
                set_once(&mut sk, req_val(args, i, "--sk")?, "--sk")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out, req_val(args, i, "--out")?, "--out")?;
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
                set_once(&mut pk, req_val(args, i, "--pk")?, "--pk")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--sig" => {
                i += 1;
                set_once(&mut sig, req_val(args, i, "--sig")?, "--sig")?;
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
    let mut secret_hex: Option<ZeroizeStr> = None;
    let mut total: Option<u8> = None;
    let mut threshold: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                i += 1;
                set_once(
                    &mut secret_hex,
                    ZeroizeStr(req_val(args, i, "--secret")?),
                    "--secret",
                )?;
            }
            "--total" | "-n" => {
                i += 1;
                let s = req_val(args, i, "--total")?;
                let v = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --total '{s}' (expected 2..=255)"))
                })?;
                set_once(&mut total, v, "--total")?;
            }
            "--threshold" | "-k" => {
                i += 1;
                let s = req_val(args, i, "--threshold")?;
                let v = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --threshold '{s}' (expected 2..=255)"))
                })?;
                set_once(&mut threshold, v, "--threshold")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    let total = total.ok_or_else(|| WilisError::CliUsage("split-key requires --total <N>".into()))?;
    let threshold = threshold
        .ok_or_else(|| WilisError::CliUsage("split-key requires --threshold <K>".into()))?;
    let secret_hex = secret_hex
        .ok_or_else(|| WilisError::CliUsage("split-key requires --secret <HEX>".into()))?
        .into_inner();
    Ok(Command::SplitKey {
        secret_hex,
        total,
        threshold,
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

fn parse_mac_cmd(args: &[String], verify: bool) -> Result<Command> {
    let mut key: Option<SecretKey> = None;
    let mut tag_hex: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut text: Option<String> = None;

    let mut i = 0;
    let mut end_of_opts = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if !end_of_opts {
            match arg {
                "--" => {
                    end_of_opts = true;
                    i += 1;
                    continue;
                }
                "--key" => {
                    i += 1;
                    set_once(&mut key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
                    i += 1;
                    continue;
                }
                "--tag" if verify => {
                    i += 1;
                    set_once(&mut tag_hex, req_val(args, i, "--tag")?, "--tag")?;
                    i += 1;
                    continue;
                }
                "--file" => {
                    i += 1;
                    set_once(&mut file_path, req_val(args, i, "--file")?, "--file")?;
                    i += 1;
                    continue;
                }
                other if other.starts_with("--") => {
                    return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
                }
                _ => {}
            }
        }
        if text.is_some() {
            return Err(WilisError::CliUsage(
                "unexpected extra positional argument".into(),
            ));
        }
        text = Some(arg.to_string());
        i += 1;
    }

    if file_path.is_some() == text.is_some() {
        return Err(WilisError::CliUsage(
            "mac requires exactly one of --file <FILE> or <TEXT>".into(),
        ));
    }

    let key = key.ok_or_else(|| WilisError::CliUsage("missing required --key <64-HEX>".into()))?;
    if verify {
        let tag_hex =
            tag_hex.ok_or_else(|| WilisError::CliUsage("mac-verify requires --tag <64-HEX>".into()))?;
        Ok(Command::MacVerify {
            key,
            tag_hex,
            file_path,
            text,
        })
    } else {
        Ok(Command::Mac {
            key,
            file_path,
            text,
        })
    }
}

fn parse_rand_cmd(args: &[String]) -> Result<Command> {
    let mut bytes: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bytes" | "-n" => {
                i += 1;
                let s = req_val(args, i, "--bytes")?;
                let b = s.parse::<usize>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --bytes '{s}'"))
                })?;
                set_once(&mut bytes, b, "--bytes")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::Rand {
        bytes: bytes.unwrap_or(32),
    })
}

fn parse_hash_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "hash requires either --file <FILE> or <TEXT>".into(),
        ));
    }
    if args[0] == "--file" {
        if args.len() != 2 {
            return Err(WilisError::CliUsage(
                "hash --file expects exactly one <FILE> path".into(),
            ));
        }
        Ok(Command::HashFile {
            path: args[1].clone(),
        })
    } else if args[0] == "--" {
        if args.len() != 2 {
            return Err(WilisError::CliUsage(
                "hash -- expects exactly one <TEXT> argument".into(),
            ));
        }
        Ok(Command::HashText {
            text: args[1].clone(),
        })
    } else if args[0].starts_with("--") {
        Err(WilisError::CliUsage(format!(
            "unknown hash option '{}'",
            args[0]
        )))
    } else if args.len() != 1 {
        Err(WilisError::CliUsage(
            "unexpected extra argument for hash".into(),
        ))
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
