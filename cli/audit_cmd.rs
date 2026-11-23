//! CLI handler for `wilis audit` — scientific cryptanalysis & statistical randomness audit.

use crate::audit::report::{format_audit_report, run_full_audit};
use crate::error::{Result, WilisError};

/// Runs the complete `Wilis` cryptanalysis audit and prints the scorecard.
pub fn run_audit() -> Result<()> {
    let summary = run_full_audit();
    print!("{}", format_audit_report(&summary));
    if !summary.overall_pass {
        return Err(WilisError::InvalidParameters(
            "one or more cryptographic audit checks failed".to_string(),
        ));
    }
    Ok(())
}
