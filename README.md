# Aletha Labs - HALO: Host Armor for Linux Operations

A Linux System Audit Library and CLI by Aletha Labs

## Overview
HALO is a modular Rust-based tool for auditing, parsing, and rendering Linux system configuration. It is designed to be simple for home users, yet powerful for sysadmins, with a focus on extensibility, actionable output, and maintainable code.

## Features
- Modular CLI command handlers for maintainability
- Audit system, user, network, and log files for best-practice permissions
- Ownership audit with UID/GID checks
- Configurable rules via TOML
- Bash completion script generation
- CLI and library APIs
- Output in JSON, CSV, and pretty text formats (JSON only for permission/ownership audits)

## Installation
Clone the repository and build with Cargo:
```bash
cargo build --release
```


## Usage
### CLI
Run the interactive CLI:
```bash
cargo run
```

Or use commands directly:
```bash
# Parse and render a file
./target/release/halo parse --file /proc/cpuinfo --format json

# Audit user files
./target/release/halo check --target user

# Audit a file with expected permissions and importance
./target/release/halo check --path /etc/shadow --expect 640 --importance high --format json

# Audit file ownership (UID/GID)
./target/release/halo check --path /etc/shadow --expect-uid 0 --expect-gid 42 --format json

# Load custom audit rules from TOML
./target/release/halo check --toml config.toml

# Generate Bash completion script
./target/release/halo bash --out halo.bash
```


### Library
Add to your Rust project and use the API:
```rust
use halo::{UserConfig, render_json};
let results = UserConfig::default().run_audit_perms();
println!("{}", render_json(&results)?);
```

## Contributing
Contributions are welcome! Please open issues or pull requests for bugs, features, or improvements.

## License
MIT

## Maintainers
- Aletha Labs

---
For more details, see the crate documentation or run `help` in the CLI.
