//! HALO CLI module
//!
//! This module implements the command-line interface for the HALO tool.
//!
//! # Features
//! - Interactive REPL loop (`halo>` prompt)
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
//! # Ownership Checks
//! To audit file ownership, use `--expect-uid` and/or `--expect-gid` with the `check` command.
//! Ownership results are displayed after permission audit results.
use crate::{
    AuditTarget, Importance, filter, handle_bash, handle_file, handle_ownership,
    handle_permissions, handle_summary, load_toml_rules, parse_mode, render, render_csv,
    render_json, render_text,
};
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
/// Handles all subcommands and dispatches to appropriate logic.
/// - `Parse`: Parses and renders a file
/// - `Check`: Audits permissions and/or ownership
/// - `Bash`: Generates bash completion script
pub fn run_command(command: &Commands) {
    match command {
        Commands::Parse {
            format,
            line,
            store,
            file,
        } => {
            let cpu_data = handle_file(file.clone());
            match render!(&cpu_data, format, line.clone()) {
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
        Commands::Check {
            target,
            path,
            format,
            expect,
            importance,
            expect_uid,
            expect_gid,
            toml,
            store,
        } => {
            if let Some(toml_path) = toml {
                match toml_path.to_str() {
                    Some(path_str) => match load_toml_rules(path_str) {
                        Ok(toml_results) => match render!(&toml_results, format) {
                            Ok(output) => print!("{}", output),
                            Err(e) => eprintln!("Error rendering output: {}", e),
                        },
                        Err(e) => eprintln!("Error loading TOML rules: {}", e),
                    },
                    None => eprintln!("Invalid TOML file path (not valid UTF-8)"),
                }
            } else {
                let parsed_mode = expect.as_ref().map(|s| parse_mode(s)).transpose();
                match parsed_mode {
                    Ok(mode_opt) => {
                        let results = handle_permissions(
                            target.clone(),
                            path.clone(),
                            mode_opt,
                            importance.clone(),
                        );
                        handle_summary(&results, store.clone(), &format);

                        let ownership_result =
                            handle_ownership(path.clone(), *expect_uid, *expect_gid);
                        if expect_uid.is_some() || expect_gid.is_some() {
                            match ownership_result {
                                Some(result) => match render!(&result, format) {
                                    Ok(o) => print!("{}", o),
                                    Err(e) => eprintln!("Error rendering ownership output: {}", e),
                                },
                                None => {
                                    println!("Ownership check could not be performed.");
                                }
                            }
                        } else {
                            println!("Ownership check not performed (no UID/GID specified).\n");
                        }
                    }
                    Err(e) => eprintln!("Error parsing expected mode: {}", e),
                }
            }
        }
        Commands::Bash { out } => {
            handle_bash(out);
        }
    }
}
