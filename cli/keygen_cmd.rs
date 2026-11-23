//! CLI handlers for `keygen` and `hash`.

use std::fs::File;
use std::io::Read;

use crate::error::Result;
use crate::hash::{hash_hex, WilisHash};
use crate::utils::hex::encode_hex;
use crate::utils::random::generate_key;
use crate::utils::zeroize::zeroize_bytes;

/// Generates a fresh 256-bit secret key and prints its hex representation and key ID.
pub fn run_keygen() -> Result<()> {
    let key = generate_key()?;
    let mut key_hex = encode_hex(key.as_bytes());
    let fingerprint = hash_hex(key.as_bytes());

    println!("Key (256-bit hex) : {key_hex}");
    println!("Key ID (WilisHash-256): {}", &fingerprint[..32]);
    // SAFETY: Overwriting UTF-8 hex bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { key_hex.as_bytes_mut() });
    Ok(())
}

/// Prints the `WilisHash-256` hex digest of a text string.
pub fn run_hash_text(text: &str) -> Result<()> {
    println!("{}", hash_hex(text.as_bytes()));
    Ok(())
}

/// Streams a file through `WilisHash-256` and prints its hex digest.
pub fn run_hash_file(path: &str) -> Result<()> {
    let mut file = File::open(path)?;
    let mut hasher = WilisHash::new();
    let mut buf = [0u8; 64 * 1024];

    let read_res = (|| -> Result<()> {
        loop {
            let n = match file.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(())
    })();
    zeroize_bytes(&mut buf);
    read_res?;

    println!("{}  {}", encode_hex(&hasher.finalize()), path);
    Ok(())
}
