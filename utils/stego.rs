//! Pure-Rust Lossless BMP (24-bit RGB) & WAV (16-bit PCM) Keyed-Scatter LSB Steganography (`WilisStego`).
//!
//! Instead of sequential LSB embedding (trivially caught by chi-squared steganalysis),
//! `WilisStego` uses `WilisXOF` seeded by a 256-bit stego key to perform a Fisher-Yates
//! permutation of carrier byte positions before embedding length-prefixed, authenticated
//! payloads across scattered LSBs (1 bit per carrier channel/sample byte).

use crate::core::constants::KEY_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::hash;
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;
use crate::xof::WilisXof;

const STEGO_MAGIC: [u8; 4] = *b"WSTG";

/// Supported lossless cover media formats detected automatically from magic headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierFormat {
    /// Uncompressed 24-bit or 32-bit Windows BMP image (`"BM"`).
    Bmp,
    /// Uncompressed 16-bit PCM RIFF/WAVE audio (`"RIFF....WAVE"`).
    Wav,
}

/// Locates the mutable sample/pixel payload range `(offset, stride)` inside a BMP or WAV file.
fn parse_carrier_region(cover: &[u8]) -> Result<(CarrierFormat, usize, usize, usize)> {
    // BMP: "BM", pixel offset at [10..14], DIB header >= 40, bpp at [28..30] (24 or 32), compression [30..34] == 0
    if cover.len() >= 54 && &cover[0..2] == b"BM" {
        let pixel_off = u32::from_le_bytes(cover[10..14].try_into().expect("4 bytes")) as usize;
        let bpp = u16::from_le_bytes(cover[28..30].try_into().expect("2 bytes"));
        let comp = u32::from_le_bytes(cover[30..34].try_into().expect("4 bytes"));
        if comp != 0 || (bpp != 24 && bpp != 32) || pixel_off >= cover.len() {
            return Err(WilisError::InvalidFormat(
                "BMP carrier must be uncompressed 24-bit or 32-bit RGB".into(),
            ));
        }
        return Ok((CarrierFormat::Bmp, pixel_off, cover.len() - pixel_off, 1));
    }

    // WAV: "RIFF" <size> "WAVE", locate "data" subchunk, verify PCM format == 1, bits_per_sample == 16
    if cover.len() >= 44 && &cover[0..4] == b"RIFF" && &cover[8..12] == b"WAVE" {
        let mut pos = 12usize;
        let mut is_pcm16 = false;
        while pos + 8 <= cover.len() {
            let chunk_id = &cover[pos..pos + 4];
            let chunk_len = u32::from_le_bytes(cover[pos + 4..pos + 8].try_into().expect("4 bytes")) as usize;
            pos += 8;
            if chunk_len > cover.len().saturating_sub(pos) {
                return Err(WilisError::InvalidFormat("truncated WAV subchunk".into()));
            }
            if chunk_id == b"fmt " && chunk_len >= 16 {
                let audio_fmt = u16::from_le_bytes(cover[pos..pos + 2].try_into().expect("2 bytes"));
                let bps = u16::from_le_bytes(cover[pos + 14..pos + 16].try_into().expect("2 bytes"));
                is_pcm16 = audio_fmt == 1 && bps == 16;
            } else if chunk_id == b"data" {
                if !is_pcm16 {
                    return Err(WilisError::InvalidFormat(
                        "WAV carrier must be uncompressed 16-bit PCM".into(),
                    ));
                }
                // Stride = 2 bytes per 16-bit sample (embed strictly in LSB of low byte -> imperceptible)
                return Ok((CarrierFormat::Wav, pos, chunk_len, 2));
            }
            pos += chunk_len + (chunk_len & 1);
        }
    }

    Err(WilisError::InvalidFormat(
        "unsupported steganography carrier (expected uncompressed 24/32-bit BMP or 16-bit PCM WAV)".into(),
    ))
}

/// Generates a deterministic Fisher-Yates shuffled index list of the first `needed_bits`
/// carrier slots using `WilisXOF(stego_key)`.
fn scattered_positions(stego_key: &[u8; KEY_BYTES], total_slots: usize, needed_bits: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..total_slots).collect();
    let mut xof = WilisXof::new(b"WSTG_PERM_V1");
    xof.absorb(stego_key);
    xof.absorb(&(total_slots as u64).to_le_bytes());

    let mut rnd_buf = [0u8; 64];
    let mut rpos = 64;
    for i in 0..needed_bits {
        if rpos + 8 > rnd_buf.len() {
            xof.squeeze(&mut rnd_buf);
            rpos = 0;
        }
        let r = u64::from_le_bytes(rnd_buf[rpos..rpos + 8].try_into().expect("8 bytes"));
        rpos += 8;
        let rem = (total_slots - i) as u64;
        let j = i + (r % rem) as usize;
        indices.swap(i, j);
    }
    zeroize_bytes(&mut rnd_buf);
    indices.truncate(needed_bits);
    indices
}

/// Returns maximum payload capacity in bytes for `cover` (excluding 16-byte internal framing).
pub fn stego_capacity_bytes(cover: &[u8]) -> Result<(CarrierFormat, usize)> {
    let (fmt, _, region_len, stride) = parse_carrier_region(cover)?;
    let total_bits = region_len / stride;
    let total_bytes = total_bits / 8;
    Ok((fmt, total_bytes.saturating_sub(16)))
}

/// Embeds `payload` (e.g., an encrypted `WILS`/`WPKE` container) into a BMP or WAV carrier
/// using `stego_key`-driven scattered LSB embedding.
pub fn stego_embed(cover: &[u8], stego_key: &[u8; KEY_BYTES], payload: &[u8]) -> Result<Vec<u8>> {
    let (_, region_off, region_len, stride) = parse_carrier_region(cover)?;
    let total_slots = region_len / stride;

    // Framed payload: [ "WSTG": 4B ][ len: u32 LE ][ hash8: 8B ][ payload... ]
    let mut framed = Vec::with_capacity(16 + payload.len());
    framed.extend_from_slice(&STEGO_MAGIC);
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let chk = hash(payload);
    framed.extend_from_slice(&chk[0..8]);
    framed.extend_from_slice(payload);

    let needed_bits = framed.len() * 8;
    if needed_bits > total_slots {
        return Err(WilisError::InvalidParameters(format!(
            "payload ({} bytes) exceeds carrier capacity ({} bytes)",
            payload.len(),
            (total_slots / 8).saturating_sub(16)
        )));
    }

    let positions = scattered_positions(stego_key, total_slots, needed_bits);
    let mut out = cover.to_vec();
    for (bit_idx, &slot) in positions.iter().enumerate() {
        let byte_val = framed[bit_idx / 8];
        let bit = (byte_val >> (bit_idx % 8)) & 1;
        let target_idx = region_off + slot * stride;
        out[target_idx] = (out[target_idx] & 0xFE) | bit;
    }
    zeroize_bytes(&mut framed);
    Ok(out)
}

/// Extracts and verifies a scattered-LSB payload from a BMP or WAV stego file using `stego_key`.
pub fn stego_extract(stego: &[u8], stego_key: &[u8; KEY_BYTES]) -> Result<Vec<u8>> {
    let (_, region_off, region_len, stride) = parse_carrier_region(stego)?;
    let total_slots = region_len / stride;
    if total_slots < 16 * 8 {
        return Err(WilisError::InvalidFormat("carrier too small to hold stego header".into()));
    }

    // Extract 16-byte header first to recover payload length
    let hdr_pos = scattered_positions(stego_key, total_slots, 16 * 8);
    let mut hdr = [0u8; 16];
    for (bit_idx, &slot) in hdr_pos.iter().enumerate() {
        let bit = stego[region_off + slot * stride] & 1;
        hdr[bit_idx / 8] |= bit << (bit_idx % 8);
    }

    if hdr[0..4] != STEGO_MAGIC {
        return Err(WilisError::AuthenticationFailed);
    }
    let payload_len = u32::from_le_bytes(hdr[4..8].try_into().expect("4 bytes")) as usize;
    let expected_chk: [u8; 8] = hdr[8..16].try_into().expect("8 bytes");
    let total_bits = (16usize.saturating_add(payload_len)).saturating_mul(8);
    if total_bits > total_slots {
        return Err(WilisError::AuthenticationFailed);
    }

    let all_pos = scattered_positions(stego_key, total_slots, total_bits);
    let mut payload = vec![0u8; payload_len];
    for (i, &slot) in all_pos[16 * 8..].iter().enumerate() {
        let bit = stego[region_off + slot * stride] & 1;
        payload[i / 8] |= bit << (i % 8);
    }

    let actual_chk = hash(&payload);
    if !ct_eq(&actual_chk[0..8], &expected_chk) {
        zeroize_bytes(&mut payload);
        return Err(WilisError::AuthenticationFailed);
    }
    Ok(payload)
}

/// Generates a minimal valid uncompressed 24-bit RGB BMP cover image (`width x height`)
/// — useful for testing and generating clean cover carriers with zero external libraries.
pub fn generate_blank_bmp(width: u32, height: u32) -> Vec<u8> {
    let row_bytes = (width as usize) * 3;
    let row_padded = row_bytes.div_ceil(4) * 4;
    let img_size = row_padded * (height as usize);
    let file_size = 54 + img_size;

    let mut bmp = vec![0u8; file_size];
    bmp[0..2].copy_from_slice(b"BM");
    bmp[2..6].copy_from_slice(&(file_size as u32).to_le_bytes());
    bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
    bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
    bmp[18..22].copy_from_slice(&width.to_le_bytes());
    bmp[22..26].copy_from_slice(&height.to_le_bytes());
    bmp[26..28].copy_from_slice(&1u16.to_le_bytes());
    bmp[28..30].copy_from_slice(&24u16.to_le_bytes());
    bmp[34..38].copy_from_slice(&(img_size as u32).to_le_bytes());
    bmp
}
