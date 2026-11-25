//! CLI handlers for `encrypt-text` and `decrypt-text` (with optional `WilisPad` & `WilisArmor`).

use crate::cli::args::AuthInput;
use crate::error::{Result, WilisError};
use crate::format::{
    decrypt_with_key, decrypt_with_passphrase_and_keyfile, encrypt_with_key,
    encrypt_with_passphrase_and_keyfile,
};
use crate::utils::armor::{armor_decode, armor_encode, looks_armored, ARMOR_MESSAGE};
use crate::utils::base64::{decode_base64, encode_base64};
use crate::utils::padding::{has_pad_magic, pad_to_block, unpad_strict};
use crate::utils::zeroize::zeroize_bytes;

/// Encrypts UTF-8 text and prints Base64 (backward-compatible wrapper).
pub fn run_encrypt(auth: AuthInput, aad: &str, plaintext: &str) -> Result<()> {
    run_encrypt_ex(auth, aad, plaintext, None, false)
}

/// Encrypts UTF-8 text with optional length-hiding `WilisPad` block size and `WilisArmor` output.
pub fn run_encrypt_ex(
    auth: AuthInput,
    aad: &str,
    plaintext: &str,
    pad_block: Option<usize>,
    armor: bool,
) -> Result<()> {
    let mut payload_buf: Vec<u8> = match pad_block {
        Some(block_size) => pad_to_block(plaintext.as_bytes(), block_size)?,
        None => plaintext.as_bytes().to_vec(),
    };

    let enc_res = match &auth {
        AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            strength,
        } => encrypt_with_passphrase_and_keyfile(
            passphrase.as_bytes(),
            keyfile_hash.as_ref(),
            &payload_buf,
            aad.as_bytes(),
            strength.to_params(),
        ),
        AuthInput::RawKey(key) => {
            encrypt_with_key(key.as_bytes(), &payload_buf, aad.as_bytes())
        }
    };
    zeroize_bytes(&mut payload_buf);
    let container = enc_res?;

    if armor {
        println!("{}", armor_encode(ARMOR_MESSAGE, &container)?);
    } else {
        println!("{}", encode_base64(&container));
    }
    Ok(())
}

/// Decodes Base64 or `WilisArmor`, verifies authentication, and prints UTF-8 plaintext.
pub fn run_decrypt(auth: AuthInput, aad: &str, ciphertext_b64: &str) -> Result<()> {
    run_decrypt_ex(auth, aad, ciphertext_b64, false)
}

/// Decodes Base64 or `WilisArmor`, verifies authentication, optionally strips `WilisPad`,
/// and prints UTF-8 plaintext.
pub fn run_decrypt_ex(
    auth: AuthInput,
    aad: &str,
    ciphertext_input: &str,
    unpad: bool,
) -> Result<()> {
    let container = if looks_armored(ciphertext_input) {
        let (_, bytes) = armor_decode(ciphertext_input, Some(ARMOR_MESSAGE))?;
        bytes
    } else {
        decode_base64(ciphertext_input)?
    };

    let mut decrypted = match &auth {
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

    let plaintext = if unpad {
        let res = unpad_strict(&decrypted);
        zeroize_bytes(&mut decrypted);
        res?
    } else {
        decrypted
    };

    let mut text = String::from_utf8(plaintext).map_err(|err| {
        let mut raw = err.into_bytes();
        let looks_padded = has_pad_magic(&raw);
        zeroize_bytes(&mut raw);
        if looks_padded {
            WilisError::InvalidEncoding(
                "decrypted payload appears padded with WilisPad; re-run with --unpad".to_string(),
            )
        } else {
            WilisError::InvalidEncoding("decrypted payload is not valid UTF-8 text".to_string())
        }
    })?;
    println!("{text}");
    // SAFETY: Overwriting UTF-8 string bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { text.as_bytes_mut() });
    Ok(())
}
