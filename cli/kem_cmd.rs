//! CLI handlers for post-quantum `WilisKEM` public-key encryption:
//! `kem-keygen`, multi-recipient streaming `pub-encrypt` (`WPKE` v2), and `pub-decrypt` (`WPKE` v1/v2 + `WilisArmor`).

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read};
use std::path::Path;

use crate::error::{Result, WilisError};
use crate::hash::hash_hex;
use crate::kem::{
    keygen, pub_decrypt, pub_decrypt_multi_stream, pub_encrypt_multi_stream, KemPublicKey,
    KemSecretKey, KEM_PK_BYTES, KEM_SK_BYTES,
};
use crate::stream::DEFAULT_CHUNK_SIZE;
use crate::utils::armor::{armor_decode, armor_encode, looks_armored, ARMOR_ENCRYPTED};
use crate::utils::zeroize::{
    create_unique_temp_file, paths_refer_to_same_file, read_bounded_file, write_atomic_file,
    write_secret_file, zeroize_bytes,
};

const MAX_ARMORED_WPKE_BYTES: usize = 64 * 1024 * 1024;

fn validate_key_prefix(out_prefix: &str) -> Result<()> {
    if out_prefix.is_empty() || out_prefix.ends_with('/') || out_prefix.ends_with('\\') {
        return Err(WilisError::InvalidParameters(
            "key output prefix must be a non-empty file prefix (not a directory)".into(),
        ));
    }
    Ok(())
}

/// Generates a post-quantum `WilisKEM` keypair (`<prefix>.wks` secret, `<prefix>.wkp` public).
pub fn run_kem_keygen(out_prefix: &str) -> Result<()> {
    validate_key_prefix(out_prefix)?;
    let (sk, pk) = keygen()?;
    let pk_path = format!("{out_prefix}.wkp");
    let sk_path = format!("{out_prefix}.wks");

    let pk_bytes = pk.to_bytes();
    let mut sk_bytes = sk.to_bytes();
    // Write secret key FIRST so a failed secret write can never leave an orphaned public key
    let write_sk = write_secret_file(Path::new(&sk_path), &sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    write_sk?;
    if let Err(e) = write_atomic_file(Path::new(&pk_path), &pk_bytes, false) {
        let _ = fs::remove_file(&sk_path);
        return Err(e);
    }

    let fingerprint = &hash_hex(&pk_bytes)[..32];
    println!("Generated Post-Quantum WilisKEM Keypair (Module-LWE 768 / q=7681 / IND-CCA2)");
    println!(
        "  Public key : {pk_path} ({} bytes — safe to share)",
        pk_bytes.len()
    );
    println!("  Secret key : {sk_path} (KEEP PRIVATE, mode 0600 on Unix)");
    println!("  Public ID  : {fingerprint}");
    Ok(())
}

/// Single-recipient public-key encryption helper (backward-compatible API wrapper).
pub fn run_pub_encrypt(pk_path: &str, aad: &str, input_path: &str, output_path: &str) -> Result<()> {
    run_pub_encrypt_multi(&[pk_path.to_string()], aad, input_path, output_path, false)
}

/// Stream-encrypts a file to `1..=64` post-quantum recipients (`WPKE` v2) with optional ASCII Armor.
pub fn run_pub_encrypt_multi(
    pk_paths: &[String],
    aad: &str,
    input_path: &str,
    output_path: &str,
    armor: bool,
) -> Result<()> {
    let in_p = Path::new(input_path);
    let out_p = Path::new(output_path);
    if paths_refer_to_same_file(in_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "output path must not overwrite the input file".into(),
        ));
    }
    for pk_path in pk_paths {
        if paths_refer_to_same_file(Path::new(pk_path), out_p) {
            return Err(WilisError::InvalidParameters(
                "output path must not overwrite a recipient public key".into(),
            ));
        }
    }
    if out_p.is_dir() {
        return Err(WilisError::InvalidParameters(format!(
            "output path '{}' is an existing directory",
            output_path
        )));
    }

    let mut pks = Vec::with_capacity(pk_paths.len());
    for pk_path in pk_paths {
        let pk = KemPublicKey::from_bytes(&read_bounded_file(Path::new(pk_path), KEM_PK_BYTES)?)?;
        pks.push(pk);
    }
    let pk_refs: Vec<&KemPublicKey> = pks.iter().collect();

    if armor {
        // Armored WPKE v2 buffers output in memory (capped to avoid OOM on multi-GB files)
        let mut reader = BufReader::new(File::open(in_p)?);
        let mut raw_packet = Vec::new();
        let (in_bytes, _) = pub_encrypt_multi_stream(
            &pk_refs,
            &mut reader,
            &mut raw_packet,
            aad.as_bytes(),
            DEFAULT_CHUNK_SIZE,
        )?;
        if raw_packet.len() > MAX_ARMORED_WPKE_BYTES {
            return Err(WilisError::InvalidFormat(
                "encrypted payload too large for --armor (omit --armor for multi-GB binary streaming)".into(),
            ));
        }
        let armored = armor_encode(ARMOR_ENCRYPTED, &raw_packet)?;
        write_atomic_file(out_p, armored.as_bytes(), false)?;
        println!(
            "Post-Quantum encrypted (WPKE v2 armored, {} recipient(s)) '{}' ({in_bytes} bytes) -> '{}' ({} bytes)",
            pks.len(),
            input_path,
            output_path,
            armored.len()
        );
        return Ok(());
    }

    let (tmp_path, tmp_file) = create_unique_temp_file(out_p, false)?;
    let res = (|| -> Result<(u64, u64)> {
        let mut reader = BufReader::new(File::open(in_p)?);
        let mut writer = BufWriter::new(tmp_file);
        let counts = pub_encrypt_multi_stream(
            &pk_refs,
            &mut reader,
            &mut writer,
            aad.as_bytes(),
            DEFAULT_CHUNK_SIZE,
        )?;
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(counts)
    })();

    match res {
        Ok((in_bytes, out_bytes)) => {
            if let Err(e) = fs::rename(&tmp_path, out_p) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            println!(
                "Post-Quantum encrypted (WPKE v2 stream, {} recipient(s)) '{}' ({in_bytes} bytes) -> '{}' ({out_bytes} bytes)",
                pks.len(),
                input_path,
                output_path
            );
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Authenticates and decrypts a `WPKE` v1, `WPKE` v2 streaming, or `WilisArmor`-wrapped file
/// using the recipient's `WKS1` secret key.
pub fn run_pub_decrypt(sk_path: &str, aad: &str, input_path: &str, output_path: &str) -> Result<()> {
    let sk_p = Path::new(sk_path);
    let in_p = Path::new(input_path);
    let out_p = Path::new(output_path);
    if paths_refer_to_same_file(in_p, out_p) || paths_refer_to_same_file(sk_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "output path must not overwrite the input file or secret key".into(),
        ));
    }
    if out_p.is_dir() {
        return Err(WilisError::InvalidParameters(format!(
            "output path '{}' is an existing directory",
            output_path
        )));
    }
    if let Ok(meta) = fs::symlink_metadata(out_p) {
        if meta.file_type().is_symlink() {
            return Err(WilisError::InvalidFormat(format!(
                "refusing to write decrypted plaintext onto symlink '{}'",
                out_p.display()
            )));
        }
    }

    let mut sk_bytes = read_bounded_file(sk_p, KEM_SK_BYTES)?;
    let sk_res = KemSecretKey::from_bytes(&sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    let sk = sk_res?;

    // Peek prefix to detect ASCII Armor vs WPKE v1 vs WPKE v2 streaming
    let mut peek_file = File::open(in_p)?;
    let mut prefix = [0u8; 16];
    let n_peek = peek_file.read(&mut prefix)?;
    drop(peek_file);
    if n_peek < 5 {
        return Err(WilisError::InvalidFormat(
            "input file is too short to be a WPKE encrypted container".into(),
        ));
    }

    let is_armored = core::str::from_utf8(&prefix[..n_peek])
        .map(looks_armored)
        .unwrap_or(false);

    if is_armored {
        let raw_text_bytes = read_bounded_file(in_p, MAX_ARMORED_WPKE_BYTES * 2)?;
        let text = core::str::from_utf8(&raw_text_bytes)
            .map_err(|_| WilisError::InvalidEncoding("armored WPKE file is not valid UTF-8".into()))?;
        let (_, packet) = armor_decode(text, Some(ARMOR_ENCRYPTED))?;
        return decrypt_wpke_buffer(&sk, &packet, aad, input_path, out_p, output_path);
    }

    if &prefix[0..4] != b"WPKE" {
        return Err(WilisError::InvalidFormat(
            "invalid magic bytes (expected 'WPKE' or WilisArmor)".into(),
        ));
    }

    match prefix[4] {
        1 => {
            let packet = fs::read(in_p)?;
            decrypt_wpke_buffer(&sk, &packet, aad, input_path, out_p, output_path)
        }
        2 => {
            let in_len = fs::metadata(in_p)?.len();
            let (tmp_path, tmp_file) = create_unique_temp_file(out_p, true)?;
            let res = (|| -> Result<u64> {
                let mut reader = BufReader::new(File::open(in_p)?);
                let mut writer = BufWriter::new(tmp_file);
                let out_bytes = pub_decrypt_multi_stream(&sk, &mut reader, &mut writer, aad.as_bytes())?;
                let file = writer.into_inner().map_err(|e| e.into_error())?;
                file.sync_all()?;
                Ok(out_bytes)
            })();
            match res {
                Ok(out_bytes) => {
                    if let Err(e) = fs::rename(&tmp_path, out_p) {
                        let _ = fs::remove_file(&tmp_path);
                        return Err(e.into());
                    }
                    println!(
                        "Post-Quantum decrypted & verified (WPKE v2 stream) '{}' ({in_len} bytes) -> '{}' ({out_bytes} bytes)",
                        input_path, output_path
                    );
                    Ok(())
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path);
                    Err(e)
                }
            }
        }
        other => Err(WilisError::InvalidFormat(format!(
            "unsupported WPKE version: {other}"
        ))),
    }
}

fn decrypt_wpke_buffer(
    sk: &KemSecretKey,
    packet: &[u8],
    aad: &str,
    input_path: &str,
    out_p: &Path,
    output_path: &str,
) -> Result<()> {
    if packet.len() < 5 || &packet[0..4] != b"WPKE" {
        return Err(WilisError::InvalidFormat(
            "invalid or truncated WPKE post-quantum encrypted packet".into(),
        ));
    }
    let (mut plaintext, label) = match packet[4] {
        1 => (pub_decrypt(sk, packet, aad.as_bytes())?, "WPKE v1"),
        2 => {
            let mut out = Vec::new();
            if let Err(e) = pub_decrypt_multi_stream(sk, &mut Cursor::new(packet), &mut out, aad.as_bytes()) {
                zeroize_bytes(&mut out);
                return Err(e);
            }
            (out, "WPKE v2")
        }
        other => {
            return Err(WilisError::InvalidFormat(format!(
                "unsupported WPKE version: {other}"
            )));
        }
    };
    let plain_len = plaintext.len();
    let write_res = write_atomic_file(out_p, &plaintext, true);
    zeroize_bytes(&mut plaintext);
    write_res?;
    println!(
        "Post-Quantum decrypted & verified ({label}) '{}' ({} bytes) -> '{}' ({plain_len} bytes)",
        input_path,
        packet.len(),
        output_path
    );
    Ok(())
}
