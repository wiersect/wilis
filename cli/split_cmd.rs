//! CLI handlers for `WilisSplit` Shamir's Secret Sharing: `split-key` and `combine-key`.

use crate::error::Result;
use crate::split::{combine_shares, split_secret, Share};
use crate::utils::hex::{decode_hex, encode_hex};
use crate::utils::zeroize::zeroize_bytes;

/// Splits a hex-encoded secret key into `total` shares requiring `threshold` shares to recover.
pub fn run_split_key(secret_hex: &str, total: u8, threshold: u8) -> Result<()> {
    let mut secret = decode_hex(secret_hex)?;
    let secret_len = secret.len();
    let shares_res = split_secret(&secret, total, threshold);
    zeroize_bytes(&mut secret);
    let shares = shares_res?;

    println!(
        "Split {secret_len}-byte secret into {total} shares (threshold k={threshold}):"
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

    let mut recovered = combine_shares(&shares)?;
    let hex_out = encode_hex(&recovered);
    zeroize_bytes(&mut recovered);
    println!("{hex_out}");
    Ok(())
}
