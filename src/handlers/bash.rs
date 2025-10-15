use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::{generate_to, shells::Bash};
use std::path::Path;

// Handler for the `bash` command
//
// Generates bash completion scripts for the CLI
pub fn handle_bash(out: &str) {
    let mut cmd = Cli::command();
    match generate_to(
        Bash,
        &mut cmd,
        "halo",
        Path::new(out).parent().unwrap_or_else(|| Path::new(".")),
    ) {
        Ok(path) => {
            println!("Bash completion script generated at: {}", path.display())
        }
        Err(e) => eprintln!("Failed to generate completion script: {}", e),
    }
}