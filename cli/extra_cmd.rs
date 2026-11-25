//! CLI handlers for Wilis v0.6.0 commands:
//! `shred`, `passgen`, `completions`, `mnemonic`, `key-protect`/`key-unlock`,
//! `keyring`, `stego`, `hidden`, `slh-keygen`/`slh-sign`/`slh-verify`,
//! `send`/`recv` (WilisNet PQ TCP), and persistent `ratchet`.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::args::{
    AuthInput, KeyringAction, NetAuthMode, PassgenMode, RatchetAction, StegoAction,
};
use crate::core::constants::KEY_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::hash_hex;
use crate::kdf::KdfStrength;
use crate::kem::{KemPublicKey, KemSecretKey};
use crate::net::{recv_file_over_tcp, recv_file_pake, send_file_over_tcp, send_file_pake};
use crate::ratchet::{
    load_pq_session, save_pq_session, HandshakeInit, PqMessagePacket, PqRatchetSession,
    PqRekeyPacket,
};
use crate::sign::{SigningKey, SlhPublicKey, SlhSecretKey, SlhSignature, VerifyingKey};
use crate::utils::armor::{armor_decode, armor_encode, looks_armored};
use crate::utils::hex::{decode_hex, encode_hex};
use crate::utils::keywrap::{unwrap_secret_key, wrap_secret_key, Keyring};
use crate::utils::memlock::shred_file;
use crate::utils::mnemonic::{decode_mnemonic, encode_mnemonic, WORDLIST_256};
use crate::utils::random::fill_random;
use crate::utils::stego::{stego_capacity_bytes, stego_embed, stego_extract};
use crate::utils::zeroize::{
    paths_refer_to_same_file, read_bounded_file, write_atomic_file, write_secret_file,
    zeroize_bytes,
};
use crate::vault::{create_deniable_container, open_deniable_container};

const MAX_KEY_FILE_BYTES: usize = 64 * 1024;
const MAX_STEGO_FILE_BYTES: usize = 128 * 1024 * 1024;
const MAX_HIDDEN_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SLH_SIGN_BYTES: usize = 64 * 1024 * 1024;
const SLH_SIG_ARMOR_LABEL: &str = "WILIS SLH SIGNATURE";
const NET_CONTEXT: &[u8] = b"wilis-net-p2p-v1";

/// Securely overwrites and deletes a regular file (`wilis shred`).
pub fn run_shred(path: &str, passes: usize) -> Result<()> {
    shred_file(Path::new(path), passes)?;
    println!("Securely shredded and removed '{path}' ({passes} pass(es))");
    Ok(())
}

/// Uniform rejection-sampled index in `[0, bound)` from OS CSPRNG (zero modulo bias).
fn uniform_usize(bound: usize) -> Result<usize> {
    if bound == 0 {
        return Err(WilisError::InvalidParameters("bound must be > 0".into()));
    }
    let limit = (u64::MAX / bound as u64) * (bound as u64);
    let mut buf = [0u8; 8];
    loop {
        fill_random(&mut buf)?;
        let val = u64::from_le_bytes(buf);
        if val < limit {
            zeroize_bytes(&mut buf);
            return Ok((val % bound as u64) as usize);
        }
    }
}

/// Generates cryptographically strong passwords or phonetic passphrases (`wilis passgen`).
pub fn run_passgen(mode: PassgenMode, length: usize, count: usize) -> Result<()> {
    if count == 0 || count > 100 {
        return Err(WilisError::InvalidParameters(
            "passgen --count must be within 1..=100".into(),
        ));
    }

    match mode {
        PassgenMode::Password => {
            if !(8..=256).contains(&length) {
                return Err(WilisError::InvalidParameters(
                    "password --length must be within 8..=256".into(),
                ));
            }
            const ALPHABET: &[u8] =
                b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}";
            for _ in 0..count {
                let mut pw = String::with_capacity(length);
                for _ in 0..length {
                    let idx = uniform_usize(ALPHABET.len())?;
                    pw.push(ALPHABET[idx] as char);
                }
                println!("{pw}");
                // SAFETY: Overwriting ASCII bytes with 0x00 preserves UTF-8 validity.
                zeroize_bytes(unsafe { pw.as_bytes_mut() });
            }
        }
        PassgenMode::Words => {
            if !(4..=32).contains(&length) {
                return Err(WilisError::InvalidParameters(
                    "passphrase --words must be within 4..=32".into(),
                ));
            }
            for _ in 0..count {
                let mut words = Vec::with_capacity(length);
                for _ in 0..length {
                    let idx = uniform_usize(WORDLIST_256.len())?;
                    words.push(WORDLIST_256[idx]);
                }
                let mut phrase = words.join("-");
                println!("{phrase}");
                // SAFETY: Overwriting ASCII bytes with 0x00 preserves UTF-8 validity.
                zeroize_bytes(unsafe { phrase.as_bytes_mut() });
            }
        }
    }
    Ok(())
}

/// Emits ready-to-source shell completion scripts (`wilis completions bash|zsh|fish|powershell`).
pub fn run_completions(shell: &str) -> Result<()> {
    const COMMANDS: &str = "encrypt-text decrypt-text encrypt-file decrypt-file encrypt-dir decrypt-dir kem-keygen pub-encrypt pub-decrypt sign-keygen sign verify slh-keygen slh-sign slh-verify vault split-key combine-key mac mac-verify hash keygen rand passgen mnemonic key-protect key-unlock keyring stego hidden send recv ratchet inspect shred completions bench audit help";
    match shell.to_ascii_lowercase().as_str() {
        "bash" => {
            println!(
                "_wilis_completions() {{\n    local cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n    if [[ ${{COMP_CWORD}} -eq 1 ]]; then\n        COMPREPLY=( $(compgen -W \"{COMMANDS}\" -- \"$cur\") )\n    else\n        COMPREPLY=( $(compgen -f -- \"$cur\") )\n    fi\n}}\ncomplete -F _wilis_completions wilis"
            );
            Ok(())
        }
        "zsh" => {
            println!(
                "#compdef wilis\nlocal -a commands\ncommands=({COMMANDS})\nif (( CURRENT == 2 )); then\n  _describe 'wilis command' commands\nelse\n  _files\nfi"
            );
            Ok(())
        }
        "fish" => {
            for cmd in COMMANDS.split_whitespace() {
                println!("complete -c wilis -n '__fish_use_subcommand' -a '{cmd}'");
            }
            Ok(())
        }
        "powershell" | "pwsh" => {
            let quoted: Vec<String> = COMMANDS
                .split_whitespace()
                .map(|c| format!("'{c}'"))
                .collect();
            println!(
                "Register-ArgumentCompleter -Native -CommandName wilis -ScriptBlock {{\n    param($wordToComplete, $commandAst, $cursorPosition)\n    @({}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}\n}}",
                quoted.join(", ")
            );
            Ok(())
        }
        other => Err(WilisError::CliUsage(format!(
            "unsupported shell '{other}' (expected: bash, zsh, fish, powershell)"
        ))),
    }
}

/// Encodes a 256-bit hex key into a 34-word checksummed phonetic mnemonic (`wilis mnemonic encode`).
pub fn run_mnemonic_encode(key_hex: &str) -> Result<()> {
    let mut raw = decode_hex(key_hex)?;
    if raw.len() != KEY_BYTES {
        zeroize_bytes(&mut raw);
        return Err(WilisError::InvalidKey(
            "mnemonic encode requires a 64-hex (32-byte) key".into(),
        ));
    }
    let mut key = [0u8; KEY_BYTES];
    key.copy_from_slice(&raw);
    zeroize_bytes(&mut raw);

    let mut phrase = encode_mnemonic(&key)?;
    zeroize_bytes(&mut key);
    println!("{phrase}");
    // SAFETY: Overwriting ASCII bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { phrase.as_bytes_mut() });
    Ok(())
}

/// Decodes a checksummed mnemonic back to a hex key (`wilis mnemonic decode`).
pub fn run_mnemonic_decode(phrase: &str) -> Result<()> {
    let mut key = decode_mnemonic(phrase)?;
    let mut hex = encode_hex(&key);
    zeroize_bytes(&mut key);
    println!("{hex}");
    // SAFETY: Overwriting ASCII hex bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { hex.as_bytes_mut() });
    Ok(())
}

/// Encrypts a raw Wilis secret key file (`.wks`, `.wsk`, `.wls`) into a `WENC` v1 envelope.
pub fn run_key_protect(in_path: &str, out_path: &str, auth: AuthInput) -> Result<()> {
    let (pass, keyfile_hash, strength) = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => (passphrase.as_bytes(), keyfile_hash.as_ref(), *strength),
        AuthInput::RawKey(_) => {
            return Err(WilisError::CliUsage(
                "key-protect requires passphrase mode (--pass or --pass-prompt)".into(),
            ));
        }
    };
    let mut raw = read_bounded_file(Path::new(in_path), MAX_KEY_FILE_BYTES)?;
    let wrapped_res = wrap_secret_key(&raw, pass, keyfile_hash, strength.to_params());
    zeroize_bytes(&mut raw);
    let wrapped = wrapped_res?;
    write_secret_file(Path::new(out_path), &wrapped)?;
    println!("Protected secret key '{in_path}' -> '{out_path}' (WENC v1, {} bytes)", wrapped.len());
    Ok(())
}

/// Decrypts a `WENC` v1 passphrase-protected secret key envelope back to raw key bytes (mode `0600`).
pub fn run_key_unlock(in_path: &str, out_path: &str, auth: AuthInput) -> Result<()> {
    let (pass, keyfile_hash) = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } => (passphrase.as_bytes(), keyfile_hash.as_ref()),
        AuthInput::RawKey(_) => {
            return Err(WilisError::CliUsage(
                "key-unlock requires passphrase mode (--pass or --pass-prompt)".into(),
            ));
        }
    };
    let wrapped = read_bounded_file(Path::new(in_path), MAX_KEY_FILE_BYTES * 2)?;
    let mut raw = unwrap_secret_key(&wrapped, pass, keyfile_hash)?;
    let out_len = raw.len();
    let res = write_secret_file(Path::new(out_path), &raw);
    zeroize_bytes(&mut raw);
    res?;
    println!("Unlocked secret key '{in_path}' -> '{out_path}' ({out_len} bytes, mode 0600)");
    Ok(())
}

/// Manages a local `WKRN` v1 trusted public-key keyring (`add`, `list`, `revoke`, `remove`, `export`).
pub fn run_keyring(file_path: &str, action: KeyringAction) -> Result<()> {
    let path = Path::new(file_path);
    let mut kr = if path.exists() {
        Keyring::load(path)?
    } else {
        Keyring::new()
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match action {
        KeyringAction::Add {
            name,
            pk_path,
            expires_days,
        } => {
            let pk_bytes = read_bounded_file(Path::new(&pk_path), MAX_KEY_FILE_BYTES)?;
            let expires_unix = expires_days
                .map(|d| now.saturating_add(d.saturating_mul(86_400)))
                .unwrap_or(0);
            kr.add_key(&name, pk_bytes, expires_unix)?;
            kr.save(path)?;
            let entry = kr.get(&name).expect("just added");
            println!(
                "Added contact '{name}' ({}, fp: {}) to '{file_path}'",
                entry.kind.label(),
                entry.fingerprint()
            );
        }
        KeyringAction::List => {
            let list = kr.list();
            if list.is_empty() {
                println!("(keyring is empty)");
            } else {
                for e in list {
                    let status = if e.revoked {
                        format!("REVOKED ({})", e.revoke_reason)
                    } else if !e.is_usable_at(now) {
                        "EXPIRED".to_string()
                    } else {
                        "ACTIVE".to_string()
                    };
                    println!(
                        "{:<20} {:<18} fp:{} [{}]",
                        e.name,
                        e.kind.label(),
                        e.fingerprint(),
                        status
                    );
                }
            }
        }
        KeyringAction::Revoke { name, reason } => {
            kr.revoke(&name, &reason)?;
            kr.save(path)?;
            println!("Revoked contact '{name}' in '{file_path}' (reason: {reason})");
        }
        KeyringAction::Remove { name } => {
            if !kr.remove(&name) {
                return Err(WilisError::InvalidFormat(format!(
                    "keyring contact '{name}' not found"
                )));
            }
            kr.save(path)?;
            println!("Removed contact '{name}' from '{file_path}'");
        }
        KeyringAction::Export { name, out_path } => {
            let entry = kr.get(&name).ok_or_else(|| {
                WilisError::InvalidFormat(format!("keyring contact '{name}' not found"))
            })?;
            if !entry.is_usable_at(now) {
                return Err(WilisError::InvalidKey(format!(
                    "refusing to export revoked or expired key '{name}'"
                )));
            }
            write_atomic_file(Path::new(&out_path), &entry.key_bytes, false)?;
            println!(
                "Exported '{}' ({}) -> '{out_path}'",
                entry.name,
                entry.kind.label()
            );
        }
    }
    Ok(())
}

/// Handles `wilis stego` (`capacity`, `embed`, `extract`).
pub fn run_stego(action: StegoAction) -> Result<()> {
    match action {
        StegoAction::Capacity { cover } => {
            let data = read_bounded_file(Path::new(&cover), MAX_STEGO_FILE_BYTES)?;
            let (fmt, cap) = stego_capacity_bytes(&data)?;
            println!("Carrier '{cover}' ({fmt:?}): maximum hidden payload = {cap} bytes");
        }
        StegoAction::Embed {
            cover,
            in_file,
            out_file,
            key,
        } => {
            if paths_refer_to_same_file(Path::new(&cover), Path::new(&out_file)) {
                return Err(WilisError::InvalidParameters(
                    "stego output must not overwrite cover file in place".into(),
                ));
            }
            let cover_bytes = read_bounded_file(Path::new(&cover), MAX_STEGO_FILE_BYTES)?;
            let mut payload = read_bounded_file(Path::new(&in_file), MAX_STEGO_FILE_BYTES)?;
            let stego_res = stego_embed(&cover_bytes, key.as_bytes(), &payload);
            let plen = payload.len();
            zeroize_bytes(&mut payload);
            let stego = stego_res?;
            write_atomic_file(Path::new(&out_file), &stego, false)?;
            println!("Embedded {plen} bytes into '{cover}' -> '{out_file}' (keyed-scatter LSB)");
        }
        StegoAction::Extract {
            in_file,
            out_file,
            key,
        } => {
            let stego_bytes = read_bounded_file(Path::new(&in_file), MAX_STEGO_FILE_BYTES)?;
            let mut extracted = stego_extract(&stego_bytes, key.as_bytes())?;
            let len = extracted.len();
            let res = write_secret_file(Path::new(&out_file), &extracted);
            zeroize_bytes(&mut extracted);
            res?;
            println!("Extracted & verified {len} hidden bytes from '{in_file}' -> '{out_file}'");
        }
    }
    Ok(())
}

/// Creates a uniform-random plausible-deniability dual-passphrase volume (`wilis hidden create`).
pub fn run_hidden_create(
    out_file: &str,
    size: usize,
    decoy_pass: &str,
    decoy_in: &str,
    hidden_pass: &str,
    hidden_in: &str,
    strength: KdfStrength,
) -> Result<()> {
    let mut decoy_data = read_bounded_file(Path::new(decoy_in), MAX_HIDDEN_FILE_BYTES)?;
    let mut hidden_data = match read_bounded_file(Path::new(hidden_in), MAX_HIDDEN_FILE_BYTES) {
        Ok(d) => d,
        Err(e) => {
            zeroize_bytes(&mut decoy_data);
            return Err(e);
        }
    };
    let blob_res = create_deniable_container(
        size,
        decoy_pass.as_bytes(),
        &decoy_data,
        hidden_pass.as_bytes(),
        &hidden_data,
        strength.to_params(),
    );
    zeroize_bytes(&mut decoy_data);
    zeroize_bytes(&mut hidden_data);
    let blob = blob_res?;
    write_atomic_file(Path::new(out_file), &blob, false)?;
    println!(
        "Created plausible-deniability container '{out_file}' ({} bytes, zero plaintext headers)",
        blob.len()
    );
    Ok(())
}

/// Unlocks either the decoy or hidden volume matching `pass` (`wilis hidden open`).
pub fn run_hidden_open(
    in_file: &str,
    out_file: &str,
    pass: &str,
    strength: KdfStrength,
) -> Result<()> {
    let blob = read_bounded_file(Path::new(in_file), MAX_HIDDEN_FILE_BYTES)?;
    let (_is_hidden, mut pt) =
        open_deniable_container(&blob, pass.as_bytes(), strength.to_params())?;
    let len = pt.len();
    let res = write_secret_file(Path::new(out_file), &pt);
    zeroize_bytes(&mut pt);
    res?;
    println!("Unlocked & verified volume from '{in_file}' -> '{out_file}' ({len} bytes)");
    Ok(())
}

/// Generates a stateless post-quantum `WilisSLH` keypair (`<PREFIX>.wls` + `<PREFIX>.wlp`).
pub fn run_slh_keygen(out_prefix: &str) -> Result<()> {
    let sk_path = format!("{out_prefix}.wls");
    let pk_path = format!("{out_prefix}.wlp");
    if fs::symlink_metadata(&sk_path).is_ok() || fs::symlink_metadata(&pk_path).is_ok() {
        return Err(WilisError::InvalidFormat(format!(
            "refusing to overwrite existing key files '{sk_path}' or '{pk_path}'"
        )));
    }
    let (sk, pk) = SlhSecretKey::generate()?;
    let mut sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();
    let res = write_secret_file(Path::new(&sk_path), &sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    res?;
    write_atomic_file(Path::new(&pk_path), &pk_bytes, false)?;
    println!("Generated stateless WilisSLH post-quantum keypair (unlimited signatures):");
    println!("  Secret key (mode 0600) : {sk_path} ({} bytes)", crate::sign::SLH_SK_BYTES);
    println!("  Public key             : {pk_path} ({} bytes)", crate::sign::SLH_PK_BYTES);
    println!("  Fingerprint            : {}", &hash_hex(&pk_bytes)[..32]);
    Ok(())
}

/// Statelessly signs a file with `WilisSLH` (`WLSG` v1, optional ASCII Armor).
pub fn run_slh_sign(sk_path: &str, in_path: &str, out_path: &str, armor: bool) -> Result<()> {
    let mut sk_bytes = read_bounded_file(Path::new(sk_path), MAX_KEY_FILE_BYTES)?;
    let sk_res = SlhSecretKey::from_bytes(&sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    let sk = sk_res?;

    let msg = read_bounded_file(Path::new(in_path), MAX_SLH_SIGN_BYTES)?;
    let sig = sk.sign(&msg)?;
    let sig_bytes = sig.to_bytes();
    if armor {
        let armored = armor_encode(SLH_SIG_ARMOR_LABEL, &sig_bytes)?;
        write_atomic_file(Path::new(out_path), armored.as_bytes(), false)?;
    } else {
        write_atomic_file(Path::new(out_path), &sig_bytes, false)?;
    }
    println!(
        "Statelessly signed '{in_path}' -> '{out_path}' (WLSG v1, {} bytes)",
        sig_bytes.len()
    );
    Ok(())
}

/// Verifies a stateless `WilisSLH` (`WLSG` v1) signature (binary or ASCII-armored).
pub fn run_slh_verify(pk_path: &str, in_path: &str, sig_path: &str) -> Result<()> {
    let pk_bytes = read_bounded_file(Path::new(pk_path), MAX_KEY_FILE_BYTES)?;
    let pk = SlhPublicKey::from_bytes(&pk_bytes)?;
    let raw_sig = read_bounded_file(Path::new(sig_path), 64 * 1024)?;
    let sig_bytes = if let Ok(text) = std::str::from_utf8(&raw_sig) {
        if looks_armored(text) {
            let (_, decoded) = armor_decode(text, Some(SLH_SIG_ARMOR_LABEL))?;
            decoded
        } else {
            raw_sig
        }
    } else {
        raw_sig
    };
    let sig = SlhSignature::from_bytes(&sig_bytes)?;
    let msg = read_bounded_file(Path::new(in_path), MAX_SLH_SIGN_BYTES)?;
    if pk.verify(&msg, &sig) {
        println!("SLH SIGNATURE VALID (WilisSLH stateless post-quantum verified)");
        Ok(())
    } else {
        Err(WilisError::AuthenticationFailed)
    }
}

/// Sends a file over a PQ encrypted TCP channel (`wilis send`).
pub fn run_send(addr: &str, file_path: &str, mode: NetAuthMode) -> Result<()> {
    let summary = match &mode {
        NetAuthMode::Pake { passphrase, strength } => {
            send_file_pake(addr, Path::new(file_path), passphrase.as_bytes(), NET_CONTEXT, strength.to_params())?
        }
        NetAuthMode::PkiSend { sign_sk_path, peer_kem_pk_path } => {
            let mut sk_bytes = read_bounded_file(Path::new(sign_sk_path), MAX_KEY_FILE_BYTES)?;
            let sk_res = SigningKey::from_bytes(&sk_bytes);
            zeroize_bytes(&mut sk_bytes);
            let mut sign_sk = sk_res?;
            let pk_bytes = read_bounded_file(Path::new(peer_kem_pk_path), MAX_KEY_FILE_BYTES)?;
            let peer_pk = KemPublicKey::from_bytes(&pk_bytes)?;

            let summary = send_file_over_tcp(addr, Path::new(file_path), &mut sign_sk, &peer_pk, NET_CONTEXT)?;
            // Persist updated stateful signing key counter immediately!
            let mut updated = sign_sk.to_bytes();
            let save_res = write_secret_file(Path::new(sign_sk_path), &updated);
            zeroize_bytes(&mut updated);
            save_res?;
            summary
        }
        NetAuthMode::PkiRecv { .. } => {
            return Err(WilisError::CliUsage("invalid auth mode for send".into()));
        }
    };
    println!(
        "Sent '{file_path}' -> {addr} ({} bytes, PCS epoch {}, WilisHash-256: {})",
        summary.bytes_sent,
        summary.final_epoch,
        encode_hex(&summary.digest)
    );
    Ok(())
}

/// Listens on TCP and receives one verified file over a PQ encrypted channel (`wilis recv`).
pub fn run_recv(listen_addr: &str, out_dir: &str, mode: NetAuthMode) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)?;
    eprintln!("Listening for post-quantum WilisNet transfer on {listen_addr}...");
    let summary = match &mode {
        NetAuthMode::Pake { passphrase, .. } => {
            recv_file_pake(&listener, Path::new(out_dir), passphrase.as_bytes(), NET_CONTEXT)?
        }
        NetAuthMode::PkiRecv { kem_sk_path, peer_vk_path } => {
            let mut sk_bytes = read_bounded_file(Path::new(kem_sk_path), MAX_KEY_FILE_BYTES)?;
            let sk_res = KemSecretKey::from_bytes(&sk_bytes);
            zeroize_bytes(&mut sk_bytes);
            let kem_sk = sk_res?;
            let vk_bytes = read_bounded_file(Path::new(peer_vk_path), MAX_KEY_FILE_BYTES)?;
            let peer_vk = VerifyingKey::from_bytes(&vk_bytes)?;
            recv_file_over_tcp(&listener, Path::new(out_dir), &kem_sk, &peer_vk, NET_CONTEXT)?
        }
        NetAuthMode::PkiSend { .. } => {
            return Err(WilisError::CliUsage("invalid auth mode for recv".into()));
        }
    };
    println!(
        "Received & verified '{}' ({} bytes, PCS epoch {}, WilisHash-256: {})",
        summary.saved_path.display(),
        summary.bytes_received,
        summary.final_epoch,
        encode_hex(&summary.digest)
    );
    Ok(())
}

/// Persistent Post-Quantum Ratchet CLI (`wilis ratchet init|accept|encrypt|decrypt|rekey|apply-rekey`).
pub fn run_ratchet(state_path: &str, auth: AuthInput, action: RatchetAction) -> Result<()> {
    let (pass, keyfile_hash, strength) = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => (passphrase.as_bytes(), keyfile_hash.as_ref(), *strength),
        AuthInput::RawKey(_) => {
            return Err(WilisError::CliUsage(
                "ratchet requires passphrase mode (--pass or --pass-prompt) to encrypt state at rest".into(),
            ));
        }
    };
    let st_path = Path::new(state_path);

    match action {
        RatchetAction::Init {
            sign_sk_path,
            peer_kem_pk_path,
            handshake_out,
            context,
        } => {
            let mut sk_bytes = read_bounded_file(Path::new(&sign_sk_path), MAX_KEY_FILE_BYTES)?;
            let sk_res = SigningKey::from_bytes(&sk_bytes);
            zeroize_bytes(&mut sk_bytes);
            let mut sign_sk = sk_res?;
            let pk_bytes = read_bounded_file(Path::new(&peer_kem_pk_path), MAX_KEY_FILE_BYTES)?;
            let peer_pk = KemPublicKey::from_bytes(&pk_bytes)?;

            let (session, init) =
                PqRatchetSession::initiate_handshake(&mut sign_sk, &peer_pk, context.as_bytes())?;
            let mut updated_sk = sign_sk.to_bytes();
            let sk_save = write_secret_file(Path::new(&sign_sk_path), &updated_sk);
            zeroize_bytes(&mut updated_sk);
            sk_save?;

            save_pq_session(st_path, &session, pass, keyfile_hash, strength.to_params())?;
            write_atomic_file(Path::new(&handshake_out), &init.to_bytes(), false)?;
            println!("Initialized PQ ratchet session at '{state_path}' (handshake -> '{handshake_out}')");
        }
        RatchetAction::Accept {
            kem_sk_path,
            peer_vk_path,
            handshake_in,
            context,
        } => {
            let mut sk_bytes = read_bounded_file(Path::new(&kem_sk_path), MAX_KEY_FILE_BYTES)?;
            let sk_res = KemSecretKey::from_bytes(&sk_bytes);
            zeroize_bytes(&mut sk_bytes);
            let kem_sk = sk_res?;
            let vk_bytes = read_bounded_file(Path::new(&peer_vk_path), MAX_KEY_FILE_BYTES)?;
            let peer_vk = VerifyingKey::from_bytes(&vk_bytes)?;
            let hs_bytes = read_bounded_file(Path::new(&handshake_in), MAX_KEY_FILE_BYTES)?;
            let init = HandshakeInit::from_bytes(&hs_bytes)?;

            let session =
                PqRatchetSession::accept_handshake(&kem_sk, &peer_vk, &init, context.as_bytes())?;
            save_pq_session(st_path, &session, pass, keyfile_hash, strength.to_params())?;
            println!("Accepted PQ handshake '{handshake_in}' and saved session state to '{state_path}'");
        }
        RatchetAction::Encrypt { in_path, out_path, aad } => {
            let mut session = load_pq_session(st_path, pass, keyfile_hash)?;
            let mut pt = read_bounded_file(Path::new(&in_path), 16 * 1024 * 1024)?;
            let pkt = session.encrypt_next(&pt, aad.as_bytes());
            zeroize_bytes(&mut pt);
            save_pq_session(st_path, &session, pass, keyfile_hash, strength.to_params())?;
            write_atomic_file(Path::new(&out_path), &pkt.to_bytes(), false)?;
            println!(
                "Ratchet-encrypted '{in_path}' -> '{out_path}' (epoch {}, msg #{})",
                pkt.epoch, pkt.inner.counter
            );
        }
        RatchetAction::Decrypt { in_path, out_path, aad } => {
            let mut session = load_pq_session(st_path, pass, keyfile_hash)?;
            let raw = read_bounded_file(Path::new(&in_path), 16 * 1024 * 1024)?;
            let pkt = PqMessagePacket::from_bytes(&raw)?;
            let mut pt = session.decrypt_packet(&pkt, aad.as_bytes())?;
            save_pq_session(st_path, &session, pass, keyfile_hash, strength.to_params())?;
            let res = write_secret_file(Path::new(&out_path), &pt);
            zeroize_bytes(&mut pt);
            res?;
            println!(
                "Ratchet-decrypted '{in_path}' -> '{out_path}' (epoch {}, msg #{})",
                pkt.epoch, pkt.inner.counter
            );
        }
        RatchetAction::Rekey { out_path } => {
            let mut session = load_pq_session(st_path, pass, keyfile_hash)?;
            let rekey = session.initiate_rekey()?;
            save_pq_session(st_path, &session, pass, keyfile_hash, strength.to_params())?;
            write_atomic_file(Path::new(&out_path), &rekey.to_bytes(), false)?;
            println!("Initiated PQ-PCS rekey to epoch {} (packet -> '{out_path}')", rekey.new_epoch);
        }
        RatchetAction::ApplyRekey { in_path } => {
            let mut session = load_pq_session(st_path, pass, keyfile_hash)?;
            let raw = read_bounded_file(Path::new(&in_path), MAX_KEY_FILE_BYTES)?;
            let rekey = PqRekeyPacket::from_bytes(&raw)?;
            session.accept_rekey(&rekey)?;
            save_pq_session(st_path, &session, pass, keyfile_hash, strength.to_params())?;
            println!("Applied PQ-PCS rekey '{in_path}' -> advanced session to epoch {}", session.epoch());
        }
    }
    Ok(())
}
