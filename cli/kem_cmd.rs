//! CLI handlers for post-quantum `WilisKEM` public-key encryption:
//! `kem-keygen`, `pub-encrypt`, and `pub-decrypt`.

use std::fs;
use std::path::Path;

use crate::error::{Result, WilisError};
use crate::hash::hash_hex;
use crate::kem::{keygen, pub_decrypt, pub_encrypt, KemPublicKey, KemSecretKey};
use crate::utils::zeroize::{
    paths_refer_to_same_file, write_atomic_file, write_secret_file, zeroize_bytes,
};

/// Generates a post-quantum `WilisKEM` keypair (`<prefix>.wkp` public, `<prefix>.wks` secret).
pub fn run_kem_keygen(out_prefix: &str) -> Result<()> {
    let (sk, pk) = keygen()?;
    let pk_path = format!("{out_prefix}.wkp");
    let sk_path = format!("{out_prefix}.wks");

    let pk_bytes = pk.to_bytes();
    let mut sk_bytes = sk.to_bytes();
    write_atomic_file(Path::new(&pk_path), &pk_bytes, false)?;
    let write_sk = write_secret_file(Path::new(&sk_path), &sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    write_sk?;

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

/// Encrypts a file directly to a recipient's post-quantum `WKP1` public key (`WPKE` v1).
pub fn run_pub_encrypt(pk_path: &str, aad: &str, input_path: &str, output_path: &str) -> Result<()> {
    let in_p = Path::new(input_path);
    let out_p = Path::new(output_path);
    if paths_refer_to_same_file(in_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "input and output paths must not refer to the same file".into(),
        ));
    }

    let pk = KemPublicKey::from_bytes(&fs::read(pk_path)?)?;
    let mut plaintext = fs::read(in_p)?;
    let in_len = plaintext.len();
    let packet_res = pub_encrypt(&pk, &plaintext, aad.as_bytes());
    zeroize_bytes(&mut plaintext);
    let packet = packet_res?;

    write_atomic_file(out_p, &packet, false)?;

    println!(
        "Post-Quantum encrypted '{}' ({in_len} bytes) -> '{}' ({} bytes) using '{}'",
        input_path,
        output_path,
        packet.len(),
        pk_path
    );
    Ok(())
}

/// Authenticates and decrypts a `WPKE` v1 file using the recipient's `WKS1` secret key.
pub fn run_pub_decrypt(sk_path: &str, aad: &str, input_path: &str, output_path: &str) -> Result<()> {
    let in_p = Path::new(input_path);
    let out_p = Path::new(output_path);
    if paths_refer_to_same_file(in_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "input and output paths must not refer to the same file".into(),
        ));
    }

    let mut sk_bytes = fs::read(sk_path)?;
    let sk_res = KemSecretKey::from_bytes(&sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    let sk = sk_res?;

    let packet = fs::read(in_p)?;
    let mut plaintext = pub_decrypt(&sk, &packet, aad.as_bytes())?;
    let plain_len = plaintext.len();

    // Decrypted plaintext is persisted atomically with owner-only (0600 on Unix) permissions
    let write_res = write_atomic_file(out_p, &plaintext, true);
    zeroize_bytes(&mut plaintext);
    write_res?;

    println!(
        "Post-Quantum decrypted & verified '{}' ({} bytes) -> '{}' ({plain_len} bytes)",
        input_path,
        packet.len(),
        output_path,
    );
    Ok(())
}
