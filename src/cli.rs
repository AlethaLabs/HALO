use crate::handlers::{handle_bash, handle_net, handle_parse, handle_check};
use crate::handlers::check::AuditTarget;
use alhalo::Importance;
use clap::{ArgGroup, Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

/// Command-line interface for HALO
#[derive(Parser, Debug)]
#[command(author = "Aletha Labs", version = "0.3.0", about = "Simple for the home user, Power for the sysadmin", long_about = None,
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

    /// Network discovery and analysis tools
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

// Core CLI loop - Interactive CLI loop for HALO
//
// Presents a `halo>` prompt and parses user commands interactively.
// Supports `parse`, `check`, `net`, `bash`, `exit`, and `help` commands.
//
pub fn cli() {
    loop {
        print!("halo> ");
        let _ = std::io::stdout().flush();

        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(0) => {
                // EOF reached (e.g., when input is piped or Ctrl+D is pressed)
                println!(); // Print newline for clean exit
                break;
            }
            Err(_) => {
                eprintln!("Failed to read input");
                continue;
            }
            Ok(_) => {} // Continue processing the input
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        if input == "exit" || input == "quit" {
            break;
        }
        if input == "help" {
            println!("Available commands: parse, check, net, bash, exit, help");
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

// Run a CLI command (for direct execution or from the interactive loop)
//
// Delegates each subcommand to a specialized handler function:
// - `Parse`: Calls `handle_parse` to parse and render a file
// - `Check`: Calls `handle_check` to audit permissions and/or ownership
// - `Net`: Calls `handle_net` to perform network discovery
// - `Bash`: Calls `handle_bash` to generate bash completion script
//
// This modular approach keeps CLI logic clean and maintainable.
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
