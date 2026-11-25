//! CLI handler for `wilis inspect <FILE>` — inspects any Wilis binary or ASCII-armored
//! container, key, signature, keyring, ratchet packet, or stego carrier without decrypting secrets.

use std::fs;
use std::path::Path;

use crate::format::{ContainerHeader, KeyMode, FORMAT_VERSION, FORMAT_VERSION_V2};
use crate::hash::hash_hex;
use crate::kem::{KemPublicKey, KemSecretKey, KEM_PK_BYTES, KEM_SK_BYTES};
use crate::sign::{SlhPublicKey, SlhSecretKey, VerifyingKey, SLH_PK_BYTES, SLH_SIG_BYTES, SLH_SK_BYTES};
use crate::utils::armor::{armor_decode, looks_armored};
use crate::utils::keywrap::Keyring;
use crate::utils::stego::stego_capacity_bytes;
use crate::utils::zeroize::read_bounded_file;
use crate::error::Result;

const MAX_INSPECT_READ: usize = 16 * 1024 * 1024;

/// Inspects a Wilis artifact file and prints structured metadata without needing secret keys.
pub fn run_inspect(path_str: &str) -> Result<()> {
    let path = Path::new(path_str);
    let meta = fs::metadata(path)?;
    let total_size = meta.len();
    let sample = if total_size <= MAX_INSPECT_READ as u64 {
        read_bounded_file(path, MAX_INSPECT_READ)?
    } else {
        // Read first 4 KiB header slice for multi-gigabyte files without loading file into RAM
        use std::io::Read;
        let mut f = fs::File::open(path)?;
        let mut buf = vec![0u8; 4096];
        let n = f.read(&mut buf)?;
        buf.truncate(n);
        buf
    };

    println!("File        : {path_str}");
    println!("Size        : {total_size} bytes");

    let (armor_label, bytes) = if let Ok(text) = std::str::from_utf8(&sample) {
        if looks_armored(text) {
            match armor_decode(text, None) {
                Ok((label, raw)) => (Some(label), raw),
                Err(_) => (None, sample),
            }
        } else {
            (None, sample)
        }
    } else {
        (None, sample)
    };

    if let Some(ref lbl) = armor_label {
        println!("Armor       : ASCII Armored ({lbl}), decoded {} bytes", bytes.len());
    }

    if bytes.len() < 4 {
        println!("Format      : Unknown / Too short ({} bytes)", bytes.len());
        return Ok(());
    }

    let magic = &bytes[0..4];
    match magic {
        b"WILS" => {
            if let Ok((hdr, hdr_len)) = ContainerHeader::parse(&bytes) {
                let ver_label = match hdr.version {
                    FORMAT_VERSION => "WILS v1 (Single-Shot AEAD)",
                    FORMAT_VERSION_V2 => "WILS v2 (Constant-Memory Chunked Stream AEAD)",
                    v => {
                        println!("Format      : WILS v{v} (Unknown Version)");
                        return Ok(());
                    }
                };
                println!("Format      : {ver_label}");
                println!("Header Size : {hdr_len} bytes");
                match hdr.mode {
                    KeyMode::RawKey => println!("Key Mode    : Raw 256-bit Key"),
                    KeyMode::Passphrase { params, .. } => {
                        println!(
                            "Key Mode    : Passphrase (WilisKDF: {} blocks ~ {:.1} MiB, {} passes)",
                            params.memory_blocks,
                            params.memory_bytes() as f64 / (1024.0 * 1024.0),
                            params.passes
                        );
                    }
                }
                if let Some(cs) = hdr.chunk_size {
                    println!("Chunk Size  : {cs} bytes");
                }
            } else {
                println!("Format      : WILS (malformed or truncated header)");
            }
        }
        b"WPKE" if bytes.len() >= 5 => {
            let ver = bytes[4];
            println!("Format      : WPKE v{ver} (WilisKEM Post-Quantum Hybrid Encryption)");
            if ver == 2 && bytes.len() >= 10 {
                let recipients = bytes[5];
                let cs = u32::from_le_bytes(bytes[6..10].try_into().expect("4 bytes"));
                println!("Recipients  : {recipients} anonymous recipient slot(s)");
                println!("Chunk Size  : {cs} bytes (streaming AEAD)");
            }
        }
        b"WSEK" if bytes.len() >= 18 => {
            let ver = bytes[4];
            let mode = if bytes[5] == 0 { "Raw Key" } else { "Passphrase (WilisKDF)" };
            let cs = u32::from_le_bytes(bytes[6..10].try_into().expect("4 bytes"));
            let pt_len = u64::from_le_bytes(bytes[10..18].try_into().expect("8 bytes"));
            println!("Format      : WSEK v{ver} (Random-Access Seekable Encrypted Container)");
            println!("Key Mode    : {mode}");
            println!("Chunk Size  : {cs} bytes | Plaintext Size: {pt_len} bytes");
        }
        b"WDIR" if bytes.len() >= 13 => {
            let ver = bytes[4];
            println!("Format      : WDIR v{ver} (WilisDir Unencrypted Archive Stream)");
            if ver == 1 {
                let cnt = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
                println!("Entries     : {cnt} file(s)");
            } else if ver == 2 && bytes.len() >= 14 {
                let comp = (bytes[5] & 1) != 0;
                let cnt = u64::from_le_bytes(bytes[6..14].try_into().expect("8 bytes"));
                println!("Entries     : {cnt} entry(s) | LZSS Compression: {comp}");
            }
        }
        b"WKP1" => {
            let valid = KemPublicKey::from_bytes(&bytes).is_ok();
            println!("Format      : WilisKEM Public Key (WKP1, expected {KEM_PK_BYTES} B)");
            println!("Integrity   : {}", if valid { "VALID" } else { "INVALID / CORRUPTED" });
            println!("Fingerprint : {}", &hash_hex(&bytes)[..32]);
        }
        b"WKS1" => {
            let valid = KemSecretKey::from_bytes(&bytes).is_ok();
            println!("Format      : WilisKEM Secret Key (WKS1, expected {KEM_SK_BYTES} B) [UNENCRYPTED]");
            println!("Integrity   : {}", if valid { "VALID" } else { "INVALID / CORRUPTED" });
        }
        b"WPK1" => {
            println!("Format      : WilisSign Stateful Verifying Public Key (WPK1)");
            if let Ok(vk) = VerifyingKey::from_bytes(&bytes) {
                println!(
                    "Tree Height : {} (capacity {} signatures) | Integrity: VALID",
                    vk.height,
                    1u64 << vk.height
                );
                println!("Fingerprint : {}", &hash_hex(&bytes)[..32]);
            } else {
                println!("Integrity   : INVALID / CORRUPTED");
            }
        }
        b"WSK1" => {
            println!("Format      : WilisSign Stateful Secret Signing Key (WSK1) [UNENCRYPTED]");
            if bytes.len() >= 9 {
                let height = bytes[4];
                let next_leaf = u32::from_le_bytes(bytes[5..9].try_into().expect("4 bytes"));
                let cap = 1u64.checked_shl(height as u32).unwrap_or(0);
                println!(
                    "Tree Height : {height} | Used Leaves: {next_leaf} / {cap} (remaining: {})",
                    cap.saturating_sub(next_leaf as u64)
                );
            }
        }
        b"WLP1" => {
            let valid = SlhPublicKey::from_bytes(&bytes).is_ok();
            println!("Format      : WilisSLH Stateless Post-Quantum Public Key (WLP1, {SLH_PK_BYTES} B)");
            println!("Integrity   : {}", if valid { "VALID" } else { "INVALID / CORRUPTED" });
            println!("Fingerprint : {}", &hash_hex(&bytes)[..32]);
        }
        b"WLS1" => {
            let valid = SlhSecretKey::from_bytes(&bytes).is_ok();
            println!("Format      : WilisSLH Stateless Post-Quantum Secret Key (WLS1, {SLH_SK_BYTES} B) [UNENCRYPTED]");
            println!("Integrity   : {}", if valid { "VALID" } else { "INVALID / CORRUPTED" });
        }
        b"WSIG" if bytes.len() >= 10 => {
            let ver = bytes[4];
            let height = bytes[5];
            let leaf = u32::from_le_bytes(bytes[6..10].try_into().expect("4 bytes"));
            println!("Format      : WilisSign Signature (WSIG v{ver})");
            println!("Merkle Leaf : #{leaf} (tree height {height})");
        }
        b"WLSG" if bytes.len() >= 5 => {
            println!(
                "Format      : WilisSLH Stateless Signature (WLSG v{}, expected {SLH_SIG_BYTES} B)",
                bytes[4]
            );
        }
        b"WPSC" if bytes.len() >= 5 => {
            println!("Format      : WilisSigncrypt Authenticated PQ Bundle (WPSC v{})", bytes[4]);
        }
        b"WENC" if bytes.len() >= 5 => {
            println!("Format      : WENC v{} Passphrase-Protected Secret Key Envelope", bytes[4]);
            if let Ok((hdr, _)) = ContainerHeader::parse(&bytes[5..]) {
                if let KeyMode::Passphrase { params, .. } = hdr.mode {
                    println!(
                        "KDF Params  : {} blocks (~{:.1} MiB), {} passes",
                        params.memory_blocks,
                        params.memory_bytes() as f64 / (1024.0 * 1024.0),
                        params.passes
                    );
                }
            }
        }
        b"WKRN" => {
            println!("Format      : WKRN v1 Trusted Public-Key Keyring");
            match Keyring::from_bytes(&bytes) {
                Ok(kr) => {
                    let entries = kr.list();
                    let revoked = entries.iter().filter(|e| e.revoked).count();
                    println!(
                        "Integrity   : VALID | Contacts: {} (active: {}, revoked: {})",
                        entries.len(),
                        entries.len() - revoked,
                        revoked
                    );
                }
                Err(_) => println!("Integrity   : INVALID / CORRUPTED"),
            }
        }
        b"WRAT" if bytes.len() >= 13 => {
            let counter = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
            println!("Format      : WRAT v{} Symmetric Ratchet Packet (msg #{counter})", bytes[4]);
        }
        b"WHSH" if bytes.len() >= 5 => {
            println!("Format      : WHSH v{} Post-Quantum Authenticated Handshake Packet", bytes[4]);
        }
        b"WRP2" if bytes.len() >= 13 => {
            let epoch = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
            println!("Format      : WRP2 v{} PQ-PCS Ratchet Message Packet (epoch {epoch})", bytes[4]);
        }
        b"WPRK" if bytes.len() >= 13 => {
            let epoch = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
            println!("Format      : WPRK v{} PQ-PCS KEM Rekey Packet (new epoch {epoch})", bytes[4]);
        }
        b"WRST" if bytes.len() >= 5 => {
            println!("Format      : WRST v{} Encrypted Persistent PQ Ratchet Session State", bytes[4]);
        }
        b"WTLK" if bytes.len() >= 13 => {
            let steps = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
            println!("Format      : WTLK v{} Sequential Time-Lock Puzzle ({steps} steps)", bytes[4]);
        }
        b"WLZ1" if bytes.len() >= 12 => {
            let orig = u64::from_le_bytes(bytes[4..12].try_into().expect("8 bytes"));
            println!("Format      : WLZ1 WilisLZ Compressed Stream (uncompressed size: {orig} bytes)");
        }
        _ => {
            if let Ok((fmt, cap)) = stego_capacity_bytes(&bytes) {
                println!("Format      : Lossless Steganography Carrier ({fmt:?})");
                println!("Stego Cap   : {cap} bytes maximum hidden payload");
            } else {
                println!("Format      : Unstructured / High-Entropy Blob (possible WilisHidden plausible-deniability volume)");
            }
        }
    }
    Ok(())
}
