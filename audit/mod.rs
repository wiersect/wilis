//! Cryptanalysis & Statistical Security Audit Suite (`wilis audit`).
//!
//! Scientifically tests `WilisPerm-384`, `WilisAEAD`, `WilisKEM`, `WilisSLH`, and PQ protocols across 8 checks:
//! 1. Round-by-round Strict Avalanche Criterion (SAC)
//! 2. Bit Independence Criterion (BIC)
//! 3. Exact Differential Distribution Table (DDT) & Linear Approximation Table (LAT) of Chi-5
//! 4. NIST SP 800-22 inspired keystream randomness battery
//! 5. Related-key sensitivity across all 256 key bits of `WilisAEAD`
//! 6. Post-quantum `WilisKEM` CCA2 correctness & implicit rejection check
//! 7. Post-quantum protocols (`WPKE` v2, PQ-PCS Ratchet, `WilisPad`)
//! 8. Empirical constant-time Welch's t-test (`dudect`) & v0.6.0 Engine (NTT, SIMD 4x, SIV, SLH)

pub mod avalanche;
pub mod key_sensitivity;
pub mod randomness;
pub mod report;
pub mod sbox_analysis;
pub mod timing;

pub use report::{run_full_audit, AuditSummary};
