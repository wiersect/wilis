//! Configurable memory-hard work-factor presets for `WilisKDF` v2.

use crate::core::constants::STATE_BYTES;
use crate::error::{Result, WilisError};

/// Approximate number of 48-byte states per MiB (`21_845 * 48 = 1,048,560 bytes`).
pub const BLOCKS_PER_MIB: u32 = 21_845;

/// Named strength presets trading interactive latency for brute-force resistance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfStrength {
    /// 16 MiB RAM, 3 passes (~100–250 ms). Strong default for daily interactive use.
    Interactive,
    /// 32 MiB RAM, 4 passes (~300–500 ms). Recommended for sensitive data.
    High,
    /// 64 MiB RAM, 6 passes (~0.8–1.5 s). Maximum offline brute-force resistance.
    Paranoid,
}

impl KdfStrength {
    /// Parses a strength preset name (`interactive`, `high`, `paranoid`).
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "interactive" | "default" => Ok(Self::Interactive),
            "high" => Ok(Self::High),
            "paranoid" | "max" => Ok(Self::Paranoid),
            other => Err(WilisError::InvalidParameters(format!(
                "unknown strength '{other}' (expected: interactive, high, paranoid)"
            ))),
        }
    }

    /// Converts the preset into concrete [`KdfParams`].
    pub fn to_params(self) -> KdfParams {
        match self {
            Self::Interactive => KdfParams::INTERACTIVE,
            Self::High => KdfParams::HIGH,
            Self::Paranoid => KdfParams::PARANOID,
        }
    }
}

/// Configurable work-factor parameters for `WilisKDF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Number of 48-byte internal states allocated in the memory-hard scratchpad.
    pub memory_blocks: u32,
    /// Number of full-memory passes (Pass 0 is data-independent; Passes 1.. are data-dependent).
    pub passes: u32,
}

impl KdfParams {
    /// Interactive default: 16 MiB RAM, 3 full passes.
    pub const INTERACTIVE: Self = Self {
        memory_blocks: 16 * BLOCKS_PER_MIB,
        passes: 3,
    };

    /// High security: 32 MiB RAM, 4 full passes.
    pub const HIGH: Self = Self {
        memory_blocks: 32 * BLOCKS_PER_MIB,
        passes: 4,
    };

    /// Paranoid security: 64 MiB RAM, 6 full passes.
    pub const PARANOID: Self = Self {
        memory_blocks: 64 * BLOCKS_PER_MIB,
        passes: 6,
    };

    /// Default preset alias ([`Self::INTERACTIVE`]).
    pub const DEFAULT: Self = Self::INTERACTIVE;

    /// Lightweight preset (~3 KiB, 2 passes) strictly for fast unit tests.
    pub const FAST_TEST: Self = Self {
        memory_blocks: 64,
        passes: 2,
    };

    /// Returns the total scratchpad memory size in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.memory_blocks as usize * STATE_BYTES
    }

    /// Validates that parameters are within safe, non-degenerate bounds.
    pub fn validate(&self) -> Result<()> {
        if self.memory_blocks < 8 {
            return Err(WilisError::InvalidParameters(
                "KDF memory_blocks must be at least 8".to_string(),
            ));
        }
        if self.passes < 2 {
            return Err(WilisError::InvalidParameters(
                "KDF passes must be at least 2 (1 data-independent + 1 data-dependent)".to_string(),
            ));
        }
        // Prevent accidental OOM DoS from malicious container headers (cap at 512 MiB)
        if self.memory_blocks > 512 * BLOCKS_PER_MIB {
            return Err(WilisError::InvalidParameters(
                "KDF memory_blocks exceeds 512 MiB safety limit".to_string(),
            ));
        }
        if self.passes > 64 {
            return Err(WilisError::InvalidParameters(
                "KDF passes exceeds safety limit (64)".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}
