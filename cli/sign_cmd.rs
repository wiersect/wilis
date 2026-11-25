//! CLI handlers for post-quantum `WilisSign`: `sign-keygen`, `sign`, and `verify`.

use std::fs;
use std::path::Path;

use crate::error::{Result, WilisError};
use crate::hash::hash_hex;
use crate::sign::{Signature, SigningKey, VerifyingKey};
use crate::utils::zeroize::{
    paths_refer_to_same_file, read_bounded_file, write_atomic_file, write_secret_file,
    zeroize_bytes,
};

/// Generates a post-quantum `WilisSign` Merkle keypair and writes `<prefix>.wsk` & `<prefix>.wpk`.
pub fn run_sign_keygen(out_prefix: &str, height: u8) -> Result<()> {
    if out_prefix.is_empty() || out_prefix.ends_with('/') || out_prefix.ends_with('\\') {
        return Err(WilisError::InvalidParameters(
            "key output prefix must be a non-empty file prefix (not a directory)".into(),
        ));
    }
    let (sk, pk) = SigningKey::generate(height)?;
    let sk_path = format!("{out_prefix}.wsk");
    let pk_path = format!("{out_prefix}.wpk");

    let mut sk_bytes = sk.to_bytes();
    let write_sk = write_secret_file(Path::new(&sk_path), &sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    write_sk?;

    let pk_bytes = pk.to_bytes();
    if let Err(e) = write_atomic_file(Path::new(&pk_path), &pk_bytes, false) {
        let _ = fs::remove_file(&sk_path);
        return Err(e);
    }

    let pk_id = &hash_hex(&pk_bytes)[..32];
    println!("Generated Post-Quantum WilisSign Keypair (WOTS+ Merkle Tree, height={height})");
    println!(
        "  Secret key : {sk_path} (KEEP PRIVATE, mode 0600 on Unix — stateful, {} signatures available)",
        sk.max_signatures()
    );
    println!("  Public key : {pk_path}");
    println!("  Public ID  : {pk_id}");
    Ok(())
}

/// Signs a file with a `WSK1` secret key, atomically advancing the stateful leaf counter.
pub fn run_sign_file(sk_path: &str, input_path: &str, sig_out_path: &str) -> Result<()> {
    let sk_p = Path::new(sk_path);
    let in_p = Path::new(input_path);
    let out_p = Path::new(sig_out_path);
    if paths_refer_to_same_file(in_p, out_p) || paths_refer_to_same_file(sk_p, out_p) {
        return Err(WilisError::InvalidParameters(
            "signature output path must not overwrite the input file or secret key".into(),
        ));
    }
    if out_p.is_dir() {
        return Err(WilisError::InvalidParameters(format!(
            "signature output path '{}' is an existing directory",
            sig_out_path
        )));
    }

    let mut sk_bytes = read_bounded_file(sk_p, 256)?;
    let sk_res = SigningKey::from_bytes(&sk_bytes);
    zeroize_bytes(&mut sk_bytes);
    let mut sk = sk_res?;

    let message = fs::read(in_p)?;
    let sig = sk.sign(&message)?;

    // Atomically persist updated secret key (O_EXCL + 0600 + sync_all) BEFORE writing signature
    let mut updated_sk_bytes = sk.to_bytes();
    let write_res = write_secret_file(sk_p, &updated_sk_bytes);
    zeroize_bytes(&mut updated_sk_bytes);
    write_res?;

    let sig_bytes = sig.to_bytes();
    write_atomic_file(out_p, &sig_bytes, false)?;

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
    let pk = VerifyingKey::from_bytes(&read_bounded_file(Path::new(pk_path), 256)?)?;
    let message = fs::read(input_path)?;
    let sig = Signature::from_bytes(&read_bounded_file(Path::new(sig_path), 4096)?)?;

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
