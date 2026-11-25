//! Entry point for the `wilis` CLI binary.

use std::env;
use std::process;

fn main() {
    // Best-effort OS hardening: disable core dumps (RLIMIT_CORE=0) & ptrace (PR_SET_DUMPABLE=0)
    wilis::utils::memlock::harden_process_memory();

    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(err) = wilis::cli::run(&args) {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
