//! CLI handlers for post-quantum `WilisKEM` public-key encryption:
//! `kem-keygen`, `pub-encrypt`, and `pub-decrypt`.

use std::fs;

use crate::error::Result;
use crate::hash::hash_hex;
use crate::kem::{keygen, pub_decrypt, pub_encrypt, KemPublicKey, KemSecretKey};

/// Generates a post-quantum `WilisKEM` keypair (`<prefix>.wkp` public, `<prefix>.wks` secret).
pub fn run_kem_keygen(out_prefix: &str) -> Result<()> {
    let (sk, pk) = keygen()?;
    let pk_path = format!("{out_prefix}.wkp");
    let sk_path = format!("{out_prefix}.wks");

    let pk_bytes = pk.to_bytes();
    fs::write(&pk_path, &pk_bytes)?;
    fs::write(&sk_path, sk.to_bytes())?;

    let fingerprint = &hash_hex(&pk_bytes)[..32];
    println!("Generated Post-Quantum WilisKEM Keypair (Module-LWE 768 / q=7681 / IND-CCA2)");
    println!("  Public key : {pk_path} ({} bytes — safe to share)", pk_bytes.len());
    println!("  Secret key : {sk_path} (KEEP PRIVATE)");
    println!("  Public ID  : {fingerprint}");
    Ok(())
}

/// Encrypts a file directly to a recipient's post-quantum `WKP1` public key (`WPKE` v1).
pub fn run_pub_encrypt(pk_path: &str, aad: &str, input_path: &str, output_path: &str) -> Result<()> {
    let pk = KemPublicKey::from_bytes(&fs::read(pk_path)?)?;
    let plaintext = fs::read(input_path)?;
    let packet = pub_encrypt(&pk, &plaintext, aad.as_bytes())?;
    fs::write(output_path, &packet)?;
    println!(
        "Post-Quantum encrypted '{}' ({} bytes) -> '{}' ({} bytes) using '{}'",
        input_path,
        plaintext.len(),
        output_path,
        packet.len(),
        pk_path
    );
    Ok(())
}

/// Authenticates and decrypts a `WPKE` v1 file using the recipient's `WKS1` secret key.
pub fn run_pub_decrypt(sk_path: &str, aad: &str, input_path: &str, output_path: &str) -> Result<()> {
    let sk = KemSecretKey::from_bytes(&fs::read(sk_path)?)?;
    let packet = fs::read(input_path)?;
    let plaintext = pub_decrypt(&sk, &packet, aad.as_bytes())?;
    fs::write(output_path, &plaintext)?;
    println!(
        "Post-Quantum decrypted & verified '{}' ({} bytes) -> '{}' ({} bytes)",
        input_path,
        packet.len(),
        output_path,
        plaintext.len()
    );
    Ok(())
}
