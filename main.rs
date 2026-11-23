//! Entry point for the `wilis` CLI binary.

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(err) = wilis::cli::run(&args) {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}
