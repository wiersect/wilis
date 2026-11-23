//! CLI handlers for `encrypt-text` and `decrypt-text`.

use crate::cli::args::AuthInput;
use crate::error::{Result, WilisError};
use crate::format::{
    decrypt_with_key, decrypt_with_passphrase_and_keyfile, encrypt_with_key,
    encrypt_with_passphrase_and_keyfile,
};
use crate::utils::base64::{decode_base64, encode_base64};
use crate::utils::zeroize::zeroize_bytes;

/// Encrypts UTF-8 text and prints the Base64-encoded `WILS` container.
pub fn run_encrypt(auth: AuthInput, aad: &str, plaintext: &str) -> Result<()> {
    let container = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => encrypt_with_passphrase_and_keyfile(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            plaintext.as_bytes(),
            aad.as_bytes(),
            strength.to_params(),
        )?,
        AuthInput::RawKey(key) => {
            encrypt_with_key(key.as_bytes(), plaintext.as_bytes(), aad.as_bytes())?
        }
    };

    println!("{}", encode_base64(&container));
    Ok(())
}

/// Decodes a Base64 `WILS` container, verifies authentication, and prints UTF-8 plaintext.
pub fn run_decrypt(auth: AuthInput, aad: &str, ciphertext_b64: &str) -> Result<()> {
    let container = decode_base64(ciphertext_b64)?;
    let plaintext = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } => decrypt_with_passphrase_and_keyfile(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            &container,
            aad.as_bytes(),
        )?,
        AuthInput::RawKey(key) => decrypt_with_key(key.as_bytes(), &container, aad.as_bytes())?,
    };

    let mut text = String::from_utf8(plaintext).map_err(|err| {
        let mut raw = err.into_bytes();
        zeroize_bytes(&mut raw);
        WilisError::InvalidEncoding("decrypted payload is not valid UTF-8 text".to_string())
    })?;
    println!("{text}");
    // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { text.as_bytes_mut() });
    Ok(())
}
