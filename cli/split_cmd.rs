//! CLI handlers for `WilisSplit` Shamir's Secret Sharing: `split-key` and `combine-key`.

use crate::error::Result;
use crate::split::{combine_shares, split_secret, Share};
use crate::utils::hex::{decode_hex, encode_hex};

/// Splits a hex-encoded secret key into `total` shares requiring `threshold` shares to recover.
pub fn run_split_key(secret_hex: &str, total: u8, threshold: u8) -> Result<()> {
    let secret = decode_hex(secret_hex)?;
    let shares = split_secret(&secret, total, threshold)?;

    println!(
        "Split {}-byte secret into {total} shares (threshold k={threshold}):",
        secret.len()
    );
    for share in &shares {
        println!("  Share {:02}/{:02}: {}", share.index, total, share.encode_string());
    }
    Ok(())
}

/// Reconstructs the original hex secret key from `K` or more share tokens.
pub fn run_combine_key(share_tokens: &[String]) -> Result<()> {
    let mut shares = Vec::with_capacity(share_tokens.len());
    for token in share_tokens {
        shares.push(Share::decode_string(token)?);
    }

    let recovered = combine_shares(&shares)?;
    println!("{}", encode_hex(&recovered));
    Ok(())
}
