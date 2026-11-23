//! CLI handlers for post-quantum `WilisSign`: `sign-keygen`, `sign`, and `verify`.

use std::fs;
use std::path::Path;

use crate::error::{Result, WilisError};
use crate::hash::hash_hex;
use crate::sign::{Signature, SigningKey, VerifyingKey};

/// Generates a post-quantum `WilisSign` Merkle keypair and writes `<prefix>.wsk` & `<prefix>.wpk`.
pub fn run_sign_keygen(out_prefix: &str, height: u8) -> Result<()> {
    let (sk, pk) = SigningKey::generate(height)?;
    let sk_path = format!("{out_prefix}.wsk");
    let pk_path = format!("{out_prefix}.wpk");

    fs::write(&sk_path, sk.to_bytes())?;
    fs::write(&pk_path, pk.to_bytes())?;

    let pk_id = &hash_hex(&pk.to_bytes())[..32];
    println!("Generated Post-Quantum WilisSign Keypair (WOTS+ Merkle Tree, height={height})");
    println!("  Secret key : {sk_path} (KEEP PRIVATE — stateful, {} signatures available)", sk.max_signatures());
    println!("  Public key : {pk_path}");
    println!("  Public ID  : {pk_id}");
    Ok(())
}

/// Signs a file with a `WSK1` secret key, atomically advancing the stateful leaf counter.
pub fn run_sign_file(sk_path: &str, input_path: &str, sig_out_path: &str) -> Result<()> {
    let sk_bytes = fs::read(sk_path)?;
    let mut sk = SigningKey::from_bytes(&sk_bytes)?;
    let message = fs::read(input_path)?;

    let sig = sk.sign(&message)?;

    // Atomically persist updated secret key BEFORE writing the signature to avoid leaf reuse
    let mut tmp_os = Path::new(sk_path).as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_sk = std::path::PathBuf::from(tmp_os);
    fs::write(&tmp_sk, sk.to_bytes())?;
    fs::rename(&tmp_sk, sk_path)?;

    let sig_bytes = sig.to_bytes();
    fs::write(sig_out_path, &sig_bytes)?;

    println!(
        "Signed '{}' -> '{}' ({} bytes, leaf #{}, {} signatures remaining)",
        input_path,
        sig_out_path,
        sig_bytes.len(),
        sig.leaf_index,
        sk.remaining_signatures()
    );
    Ok(())
}

/// Verifies a `WSIG` signature over a file using a `WPK1` public key.
pub fn run_verify_file(pk_path: &str, input_path: &str, sig_path: &str) -> Result<()> {
    let pk = VerifyingKey::from_bytes(&fs::read(pk_path)?)?;
    let message = fs::read(input_path)?;
    let sig = Signature::from_bytes(&fs::read(sig_path)?)?;

    if pk.verify(&message, &sig) {
        println!(
            "SIGNATURE VALID: '{}' authenticated by '{}' (leaf #{})",
            input_path, pk_path, sig.leaf_index
        );
        Ok(())
    } else {
        Err(WilisError::AuthenticationFailed)
    }
}
