//! Deterministic 256-word phonetic mnemonic backup (`WilisMnemonic`) with 16-bit
//! `WilisHash-256` typo-detection checksum (zero external dependencies).
//!
//! Each word encodes exactly 1 byte (`8` bits). A 32-byte (256-bit) key encodes into
//! 34 distinct words (32 payload words + 2 checksum words).

use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::utils::constant_time::ct_eq;
use crate::utils::zeroize::zeroize_bytes;

/// Curated 256-word distinct lowercase English wordlist (zero duplicates, easy paper backup).
pub const WORDLIST_256: [&str; 256] = [
    "acorn", "agate", "alder", "amber", "anchor", "anvil", "apple", "apron",
    "arbor", "arrow", "aspen", "atlas", "attic", "audio", "aurora", "autumn",
    "badge", "baker", "bamboo", "banjo", "baron", "basil", "basin", "beacon",
    "beech", "berry", "bison", "blade", "blaze", "bloom", "board", "boulder",
    "brave", "breeze", "brick", "bridge", "brook", "brush", "cabin", "cable",
    "cactus", "cairn", "camel", "canal", "candle", "canoe", "canyon", "carbon",
    "cargo", "carve", "castle", "cedar", "cello", "chalk", "charm", "chart",
    "chess", "chime", "cider", "cinder", "cipher", "citrus", "clasp", "cliff",
    "cloak", "clock", "cloud", "clover", "cobalt", "cobra", "cocoa", "comet",
    "compass", "copper", "coral", "cornet", "cotton", "cougar", "cradle", "crane",
    "crater", "creek", "crest", "cricket", "crown", "crystal", "cyclone", "cypress",
    "dagger", "dahlia", "daisy", "dancer", "dawn", "delta", "denim", "desert",
    "dewdrop", "diamond", "diesel", "dolphin", "domino", "dragon", "drift", "drum",
    "eagle", "earth", "ebony", "echo", "eclipse", "elder", "ember", "emerald",
    "engine", "epoch", "equinox", "ermine", "falcon", "fathom", "feather", "fennel",
    "ferret", "fiddle", "field", "figment", "filter", "finch", "fjord", "flame",
    "flannel", "flint", "flora", "flute", "forest", "forge", "fossil", "fountain",
    "foxtrot", "frost", "galaxy", "garnet", "gazelle", "geyser", "ginger", "glacier",
    "glider", "globe", "granite", "gravel", "griffin", "grove", "guitar", "harbor",
    "harvest", "hawk", "hazel", "hearth", "helium", "herald", "heron", "hickory",
    "hollow", "honey", "horizon", "hornet", "hunter", "hydra", "ibex", "icicle",
    "igloo", "indigo", "ingot", "inlet", "iris", "iron", "island", "ivory",
    "jacket", "jade", "jaguar", "jasmine", "jasper", "javelin", "jester", "jigsaw",
    "juniper", "kayak", "kelp", "kernel", "kestrel", "kettle", "keystone", "kiln",
    "kingdom", "kite", "knight", "koala", "krypton", "lagoon", "lantern", "larch",
    "laser", "laurel", "lava", "lemon", "leopard", "lichen", "lilac", "linden",
    "linen", "lizard", "lobster", "locket", "lotus", "lumber", "lunar", "lynx",
    "magnet", "magpie", "maple", "marble", "marina", "marten", "meadow", "mercury",
    "merlin", "meteor", "mica", "millet", "mineral", "mint", "mirage", "mirror",
    "monarch", "monsoon", "mortar", "mosaic", "mountain", "mulberry", "mustang", "myrtle",
    "narwhal", "nebula", "nectar", "needle", "neon", "nettle", "nickel", "nimbus",
    "nomad", "noodle", "north", "nutmeg", "oasis", "obsidian", "ocean", "octave",
];

fn mnemonic_checksum(payload: &[u8]) -> [u8; 2] {
    let mut h = WilisHash::new();
    h.update(b"WMNM_CHK_V1");
    h.update(&(payload.len() as u64).to_le_bytes());
    h.update(payload);
    let d = h.finalize();
    [d[0], d[1]]
}

/// Encodes `secret` bytes (non-empty) into a space-separated mnemonic phrase with 16-bit checksum.
pub fn encode_mnemonic(secret: &[u8]) -> Result<String> {
    if secret.is_empty() {
        return Err(WilisError::InvalidParameters(
            "mnemonic payload must not be empty".into(),
        ));
    }
    let chk = mnemonic_checksum(secret);
    let mut words = Vec::with_capacity(secret.len() + 2);
    for &b in secret {
        words.push(WORDLIST_256[b as usize]);
    }
    words.push(WORDLIST_256[chk[0] as usize]);
    words.push(WORDLIST_256[chk[1] as usize]);
    Ok(words.join(" "))
}

/// Decodes and checksum-verifies a `WilisMnemonic` phrase (case-insensitive whitespace-separated).
pub fn decode_mnemonic(phrase: &str) -> Result<Vec<u8>> {
    let tokens: Vec<&str> = phrase.split_whitespace().collect();
    if tokens.len() < 3 {
        return Err(WilisError::InvalidEncoding(
            "mnemonic phrase too short (must have at least 1 payload word + 2 checksum words)".into(),
        ));
    }
    let mut raw = Vec::with_capacity(tokens.len());
    for tok in tokens {
        let lower = tok.to_ascii_lowercase();
        let idx = WORDLIST_256.iter().position(|&w| w == lower).ok_or_else(|| {
            zeroize_bytes(&mut raw);
            WilisError::InvalidEncoding(format!("unknown mnemonic word '{tok}'"))
        })?;
        raw.push(idx as u8);
    }

    let split_at = raw.len() - 2;
    let payload = &raw[..split_at];
    let stored_chk = &raw[split_at..];
    let expected_chk = mnemonic_checksum(payload);
    if !ct_eq(stored_chk, &expected_chk) {
        zeroize_bytes(&mut raw);
        return Err(WilisError::AuthenticationFailed);
    }

    let out = payload.to_vec();
    zeroize_bytes(&mut raw);
    Ok(out)
}
