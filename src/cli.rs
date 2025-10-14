//! HALO CLI module
//!
//! This module implements the command-line interface for the HALO tool.
//!
//! # Features
//! - Interactive REPL loop (`halo>` prompt)
//! - Modular command dispatch via handler functions
//! - `parse` command: Parse and render system files in various formats
//! - `check` command: Audit file permissions and ownership
//!   - Supports permission checks (octal, symbolic)
//!   - Supports ownership checks via `--expect-uid` and `--expect-gid`
//!   - Can load custom audit rules from TOML
//! - Output formats: pretty, json, csv
//! - Bash completion script generation
//!
//! # Example Usage
//!
//! ```bash
//! halo parse --file /proc/cpuinfo --format json
//! halo check --path /etc/shadow --expect 640 --expect-uid 0 --expect-gid 42 --format json
//! halo check --target user
//! halo check --toml config.toml
//! ```
//!
//! # Design Notes
//!
//! The CLI command dispatch is handled by `run_command`, which delegates to specialized handler functions for each command (`handle_parse`, `handle_check`, etc.). This keeps the CLI logic clean and maintainable.
//!
//! # Ownership Checks
//! To audit file ownership, use `--expect-uid` and/or `--expect-gid` with the `check` command.
//! Ownership results are displayed after permission audit results.
use crate::handle_args::{
    AuditTarget, handle_bash, handle_file, handle_ownership, handle_permissions, handle_toml, handle_net,
};
use alhalo::{Importance, parse_mode};
use clap::{ArgGroup, Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

/// Command-line interface for HALO
#[derive(Parser, Debug)]
#[command(author = "Aletha Labs", version = "0.0.1", about = "Simple for the home user, Power for the sysadmin", long_about = None,
help_template = "\
{name}-{version} - {author}
{about}
{all-args}
")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// CLI commands for HALO
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Parse a file and render output in the selected format
    Parse {
        #[arg(
            short = 'F',
            long,
            help = "Specifies a file to parse: Example - parse --file /proc/cpuinfo"
        )]
        file: Option<PathBuf>,

        #[arg(short = 'f', long, value_parser = ["pretty", "json", "csv"], default_value = "pretty",
        help = "Select format output of chosen file: Example - parse -F /proc/cpuinfo --format json")]
        format: Option<String>,

        #[arg(
            short = 'l',
            long,
            help = "Select line to parse: Example - parse file /proc/cpuinfo --line processor"
        )]
        line: Option<Vec<String>>,

        #[arg(short = 's', long, help = "Store output to file")]
        store: Option<PathBuf>,
    },

    /// Check file permissions and/or ownership
    #[clap(
        group(
            ArgGroup::new("audit")
                .required(false)
                .args(&["target", "path"])
        ),
        group(
            ArgGroup::new("config")
                .required(false)
                .args(&["toml"])
        ),
    )]
    Check {
        #[arg(
            value_enum,
            short = 't',
            long,
            group = "audit",
            help = "Select target files to check permissions: Example - check --target user"
        )]
        target: Option<AuditTarget>,
        #[arg(
            short = 'p',
            long,
            group = "audit",
            help = "Specify a path to check permissions, a file, or directory: Example - check --path /etc/shadow <expected_permissions, importance>"
        )]
        path: Option<PathBuf>,
        #[arg(
            short = 'f',
            long,
            default_value = "json",
            help = "Specify format to render audit results: Example - check -p /etc/shadow -f json"
        )]
        format: Option<String>,
        #[arg(
            short = 'e',
            long,
            requires = "path",
            help = "Specify expected mode for permissions. Accepts octal (640), long symbolic (rw-r-----), or short symbolic (u=rw,g=r,o=). Examples:\n  check -p /etc/shadow --expect 640\n  check -p /etc/shadow --expect rw-r-----\n  check -p /etc/shadow --expect u=rw,g=r,o=\n  check -p /etc/shadow --expect u+rwx,g+rx,o+r <Importance>"
        )]
        expect: Option<String>,
        #[arg(
            value_enum,
            default_value = "medium",
            short = 'i',
            long,
            requires = "path",
            help = "Specify the importance of given file: Example - check -p /etc/shadow -e 640 -i high"
        )]
        importance: Option<Importance>,
        #[arg(
            short = 'U',
            long,
            requires = "path",
            help = "Specify expected UID for ownership check: Example - check -p /etc/shadow --expect-uid 0"
        )]
        expect_uid: Option<u32>,
        #[arg(
            short = 'G',
            long,
            requires = "path",
            help = "Specify expected GID for ownership check: Example - check -p /etc/shadow --expect-gid 42"
        )]
        expect_gid: Option<u32>,
        #[arg(
            short = 'T',
            long,
            help = "Select toml config file to load audit rules from: Example - check --toml config.toml"
        )]
        toml: Option<PathBuf>,
        #[arg(short = 's', long, help = "Store JSON output to file")]
        store: Option<PathBuf>,
    },
    Net {
        #[arg(
            short = 'f',
            long,
            help = "Specify format output: Example - net --format json"
        )]
        format: Option<String>,

        #[arg(
            short = 'd',
            long,
            action = clap::ArgAction::SetTrue,
            help = "Scan your network for devices: Example - net --devices"
        )]
        devices: bool,
    },

    /// Generate a Bash completion script for the CLI
    Bash {
        #[arg(short, long, default_value = "halo.bash")]
        out: String,
    },
}

/// Core CLI loop
/// Interactive CLI loop for HALO
///
/// Presents a `halo>` prompt and parses user commands interactively.
/// Supports `parse`, `check`, `exit`, and `help` commands.
///
/// Usage:
/// ```text
/// halo> check --path /etc/shadow --expect 640 --expect-uid 0 --expect-gid 42
/// halo> parse --file /proc/cpuinfo --format json
/// ```
pub fn cli() {
    loop {
        print!("halo> ");
        let _ = std::io::stdout().flush();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            eprintln!("Failed to read input");
            continue;
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        if input == "exit" || input == "quit" {
            break;
        }
        if input == "help" {
            println!("Available commands: parse, check, exit, help");
            continue;
        }

        // Split input into arguments, prepend binary name
        let args = std::iter::once("halo")
            .chain(input.split_whitespace())
            .collect::<Vec<_>>();

        match Cli::try_parse_from(args) {
            Ok(cli) => run_command(&cli.command),
            Err(e) => eprintln!("{}", e),
        }
    }
}

/// Run a CLI command (for direct execution or from the interactive loop)
///
/// Delegates each subcommand to a specialized handler function:
/// - `Parse`: Calls `handle_parse` to parse and render a file
/// - `Check`: Calls `handle_check` to audit permissions and/or ownership
/// - `Bash`: Calls `handle_bash` to generate bash completion script
///
/// This modular approach keeps CLI logic clean and maintainable.
pub fn run_command(command: &Commands) {
    match command {
        Commands::Parse {
            format,
            line,
            store,
            file,
        } => {
            handle_parse(file, format, line, store);
        }
        Commands::Check {
            target,
            path,
            format,
            expect,
            importance,
            expect_uid,
            expect_gid,
            store,
            toml,
        } => {
            handle_check(
                target, path, format, expect, importance, expect_uid, expect_gid, store, toml,
            );
        }
        Commands::Net { format, devices } => {
            handle_net(format, *devices);
        }
        Commands::Bash { out } => {
            handle_bash(out);
        }
    }
}

/// Handler for the `parse` command
///
/// Parses the specified file and renders output in the selected format
/// Optionally stores output to a file
fn handle_parse(
    file: &Option<PathBuf>,
    format: &Option<String>,
    line: &Option<Vec<String>>,
    store: &Option<PathBuf>,
) {
    use alhalo::{ParsedData, Renderable, OutputFormat};
    
    let data = handle_file(file.as_ref().map(|p| p.to_owned()));
    let filter_keys = line.as_ref().cloned().unwrap_or_default();
    let parsed_data = ParsedData::with_filter(data, filter_keys);
    
    let output_format = OutputFormat::from_str(format.as_deref());
    match parsed_data.render(output_format) {
        Ok(output) => {
            print!("{}", output);
            if let Some(path) = store {
                if let Err(e) = std::fs::write(path, &output) {
                    eprintln!("Failed to store output: {}", e);
                } else {
                    println!("Output stored to {}", path.display());
                }
            }
        }
        Err(e) => eprintln!("Error rendering output: {}", e),
    }
}

/// Handler for the `check` command.
///
/// Audits file permissions and/or ownership based on CLI arguments.
/// Supports permission checks, ownership checks, and TOML config loading.
/// Results are rendered and printed in the selected format.
fn handle_check(
    target: &Option<AuditTarget>,
    path: &Option<PathBuf>,
    format: &Option<String>,
    expect: &Option<String>,
    importance: &Option<Importance>,
    expect_uid: &Option<u32>,
    expect_gid: &Option<u32>,
    store: &Option<PathBuf>,
    toml: &Option<PathBuf>,
) {
    if toml.is_some() {
        handle_toml();
        return;
    }
    let permission_args = target.is_some() || (expect.is_some() && importance.is_some());
    let ownership_args = expect_uid.is_some() || expect_gid.is_some();

    if permission_args && ownership_args {
        let parsed_mode = expect.as_ref().map(|s| parse_mode(s)).transpose();
        match parsed_mode {
            Ok(mode_opt) => {
                handle_permissions(
                    target.as_ref().map(|t| t.to_owned()),
                    path.as_ref().map(|p| p.to_owned()),
                    mode_opt,
                    importance.as_ref().map(|i| i.to_owned()),
                    store.as_ref().map(|s| s.to_owned()),
                    format,
                );
            }
            Err(e) => eprintln!("Error parsing expected mode: {}", e),
        }
        handle_ownership(
            path.as_ref().map(|p| p.to_owned()),
            *expect_uid,
            *expect_gid,
            format,
        );
    } else if permission_args {
        let parsed_mode = expect.as_ref().map(|s| parse_mode(s)).transpose();
        match parsed_mode {
            Ok(mode_opt) => {
                handle_permissions(
                    target.as_ref().map(|t| t.to_owned()),
                    path.as_ref().map(|p| p.to_owned()),
                    mode_opt,
                    importance.as_ref().map(|i| i.to_owned()),
                    store.as_ref().map(|s| s.to_owned()),
                    format,
                );
            }
            Err(e) => eprintln!("Error parsing expected mode: {}", e),
        }
    } else if ownership_args {
        handle_ownership(
            path.as_ref().map(|p| p.to_owned()),
            *expect_uid,
            *expect_gid,
            format,
        );
    } else {
        println!("No valid permission or ownership audit arguments provided.\n");
    }
}
