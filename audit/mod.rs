//! Cryptanalysis & Statistical Security Audit Suite (`wilis audit`).
//!
//! Scientifically tests `WilisPerm-384`, `WilisAEAD`, and `WilisKEM` across 6 checks:
//! 1. Round-by-round Strict Avalanche Criterion (SAC)
//! 2. Bit Independence Criterion (BIC)
//! 3. Exact Differential Distribution Table (DDT) & Linear Approximation Table (LAT) of Chi-5
//! 4. NIST SP 800-22 inspired keystream randomness battery
//! 5. Related-key sensitivity across all 256 key bits of `WilisAEAD`
//! 6. Post-quantum `WilisKEM` CCA2 correctness & implicit rejection check

pub mod avalanche;
pub mod key_sensitivity;
pub mod randomness;
pub mod report;
pub mod sbox_analysis;

pub use report::{run_full_audit, AuditSummary};
