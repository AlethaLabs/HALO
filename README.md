[![Crates.io](https://img.shields.io/crates/v/alhalo.svg)](https://crates.io/crates/alhalo)
[![Docs.rs](https://docs.rs/alhalo/badge.svg)](https://docs.rs/alhalo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
# Aletha Labs - HALO: Host Armor for Linux Operations
<p  align="center">
    <img src="/assets/al_halo_nobg.png" alt="AL: HALO Logo" width="450"/>
</p>

A Linux System Audit Library and CLI by Aletha Labs

## Overview
HALO is a modular Rust-based tool for auditing, parsing, and rendering Linux system configuration. It is designed to be simple for home users, yet powerful for sysadmins, with a focus on extensibility, actionable output, and maintainable code.

## Architecture & Modularity
HALO separates its CLI and library code for maintainability and extensibility:
- The CLI (`src/cli.rs`) parses commands and dispatches to handler functions for each command.
- Handler functions in `src/handle_args.rs` perform the actual work (parsing, auditing, rendering).
- The library (`src/`) provides core audit logic, config loading, and output rendering.
This modular structure makes it easy to add new CLI commands or audit rules.

## Features
- **System Audits**: Audit system, user, network, and log files for best-practice permissions
- **Ownership Audits**: UID/GID checks with detailed reporting
- **Network Discovery**: Scan and analyze local network devices via ARP table
- **Symlink Audits**: Check symlink existence and target validation
- **Configurable Rules**: Define custom audit rules via TOML configuration
- **Multiple Output Formats**: JSON, CSV, text, and pretty-print formats
- **Trait-Based Rendering**: Consistent, extensible output formatting system
- **Interactive Fixes**: Automatically generate and apply permission fix scripts
- **Bash Completion**: Generate completion scripts for enhanced CLI experience
- **Library APIs**: Comprehensive Rust API for integration - see [docs](https://docs.rs/alhalo)
- **Interactive CLI**: REPL-style interface for efficient system administration 

## Build From Repository
This is a rust program, so rust is required to build the library.
If you need help with installing rust check out the - [Rust Installation Guide](https://www.rust-lang.org/tools/install)

- You will need to have git installed, to be sure you have git, type into your terminal:
```bash
git --version
```
- After rust is installed and you confirmed your git installation, you can clone this repository
```bash
mkdir halo_build
cd halo_build
git clone https://github.com/AlethaLabs/HALO.git
```
- Then build with rusts package manager/build tool - Cargo:
```bash
cargo build --release
```
## Quick Start

### CLI
Run the interactive CLI:
```bash
cargo run
Welcome to Aletha Labs: HALO - Host Armor for Linux Operations

Please enter your commands, or type 'help' for further information
halo> check --target user
[
    {
      "severity": "None",
      "status": "Pass",
      "path": "/etc/passwd",
      "expected_mode": "644",
      "found_mode": "644",
      "importance": "Medium"
    },
  { 
     ...
  }
]
Summary: 29 checked, 27 passed, 0 strict, 2 failed
[!] FAIL: /etc/shadow (found: 640, expected: 600)
    Suggested fix: chmod 600 /etc/shadow

Would you like to apply the suggested fixes? [y/N]: y

 --- Permission Fix Generated ---
 #!/bin/bash
 # Halo Permission Fix Script

chmod 600 /etc/shadow

Run suggested fixes? [y/N]: y
Running fix script as root (requires sudo)...
[sudo] password for AlethaLabs: password123
Permissions fixed 
.....
```

Or use commands directly:
```bash
# Get help for commands
cargo run help
cargo run check --help
cargo run parse --help
./target/release/alhalo check --target -h

# Parse and render a file
cargo run parse --file /proc/cpuinfo --format json

# Network discovery - scan local network devices
cargo run net --devices --format json
cargo run net -d  # Pretty print format

# Run both permissions and ownership audit at once
cargo run check --path /etc/shadow --expect 600 --importance high --expect-uid 0 --expect-gid 42 --format json

# Audit user files
./target/release/alhalo check --target user

# Audit a file with expected permissions and importance
./target/release/alhalo check --path /etc/shadow --expect 640 --importance high 

# Audit file ownership (UID/GID)
./target/release/alhalo check --path /etc/shadow --expect-uid 0 --expect-gid 42 

# Load custom audit rules from TOML
cargo run check --toml config.toml

# Generate Bash completion script
./target/release/alhalo bash --out halo.bash
source halo.bash
```
### Run examples
```bash
./target/release/alhalo check --toml /examples/toml_configs/permissions_config.toml
cargo run --example audit_permissions
```
### Library API

Add to your Rust project and use the API - See [docs](https://docs.rs/alhalo):
```bash
cargo add alhalo
```

### Main Structs & Functions

- **PermissionRules**: Defines files/directories to audit with expected permissions and importance. Use `PermissionRules::new()` to create audit rules.
- **Devices**: Represents network devices discovered via ARP table parsing. Implements the `Renderable` trait for consistent output formatting.
- **PermissionResults, OwnershipResult**: Results of permission and ownership audits, including severity, status, paths, expected vs found values, and errors.
- **UserConfig, SystemPermissionConfig, NetworkConfig, LogConfig**: Built-in audit targets for different system components. Each provides audit methods.
- **Renderable trait**: Unified rendering interface implemented by all data structures for consistent output across formats (JSON, CSV, Pretty, Text).
- **OutputFormat**: Enum supporting Json, Csv, Pretty, and Text output formats.
- **Severity**: Enum for marking audit findings as Critical, High, Medium, Low, or None.
- **get_arp_devices()**: Function to discover network devices by parsing the system ARP table.
- **render_and_print()**: Method available on all `Renderable` types for consistent output formatting.

#### Example
```rust
use alhalo::{
    audit::{PermissionRules, Importance, default_permissions::SystemPermissionConfig},
    render_output::{Renderable, OutputFormat}
};

// Network device discovery
let devices = alhalo::audit::networking::discovery::get_arp_devices()
    .expect("Failed to discover network devices");
devices.render_and_print(&OutputFormat::Json);

// Define custom audit rules
let (rule, _status) = PermissionRules::new("/etc/shadow".into(), 0o600, Importance::High);
let mut visited = std::collections::HashSet::new();
let results = rule.check(&mut visited);
results.render_and_print(&OutputFormat::Pretty);

// Use custom audit for simpler one-off checks
let results = PermissionRules::custom_audit("/etc/shadow".into(), 0o600, Importance::High);
results.render_and_print(&OutputFormat::Csv);

// Use default system audits
let system_config = SystemPermissionConfig::default();
let results = system_config.audit_permissions();
results.render_and_print(&OutputFormat::Csv);
```
## Minimum Supported Rust Version
This crate is tested with Rust 1.65 and newer. Please use a recent stable toolchain for best results.

## Contributing
Contributions are welcome! Please open issues or pull requests for bugs, features, or improvements.

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to add new CLI commands or audit rules
- Modular workflow for CLI and library contributions
- Coding standards and review process

## License
MIT

## Maintainers
- Aletha Labs

---
For more details, see the [crate documentation](https://docs.rs/alhalo) or run `--help` in the CLI.
## Extensibility & Testing
- Add new audit rules by extending the library modules and updating the CLI dispatcher.
- Add new CLI commands by updating the `Commands` enum and adding handler functions.
- Unit tests are in `src/` modules; integration tests are in `tests/`.
