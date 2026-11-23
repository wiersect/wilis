//! Cryptanalysis & Statistical Security Audit Suite (`wilis audit`).
//!
//! Scientifically tests `WilisPerm-384` and `WilisAEAD` across:
//! - Round-by-round Strict Avalanche Criterion (SAC) and Bit Independence Criterion (BIC)
//! - Exact Differential Distribution Table (DDT) & Linear Approximation Table (LAT) of Chi-5
//! - NIST SP 800-22 inspired keystream randomness battery (Monobit, Runs, Shannon Entropy,
//!   Chi-Squared uniformity, and Autocorrelation)

pub mod avalanche;
pub mod randomness;
pub mod report;
pub mod sbox_analysis;

pub use report::{run_full_audit, AuditSummary};
