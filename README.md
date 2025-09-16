# Aletha Labs - HALO: Host Armor for Linux Operations
<p  align="center">
    <img src="/assets/al_halo_nobg.png" alt="AL: HALO Logo" width="450"/>
</p>

A Linux System Audit Library and CLI by Aletha Labs

## Overview
HALO is a modular Rust-based tool for auditing, parsing, and rendering Linux system configuration. It is designed to be simple for home users, yet powerful for sysadmins, with a focus on extensibility, actionable output, and maintainable code.

## Features
- Audit system, user, network, and log files for best-practice permissions
- Ownership audit with UID/GID checks
- Configurable rules via TOML
- Bash completion script generation
- Library APIs - see [docs](https://docs.rs/alhalo)
- Interactive CLI (must build from this [repository source](https://github.com/AlethaLabs/HALO.git))
- Output in JSON, CSV, and pretty text formats (JSON only for permission/ownership audits)

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

- **AuditRule**: Defines a file or directory to audit, expected permissions, and importance. Use `AuditRule::new()` to create an audit rule.
- **UserConfig, SysConfig, NetConf, Log**: Built-in audit targets for user, system, network, and log files. Each provides a `.run_audit()` method to perform audits.
- **PermissionResults**: The result of a permission audit, including severity, status, path, expected and found modes, and errors.
- **Importance**: Enum for marking files as High, Medium, or Low importance in audits.
- **PathStatus**: Enum indicating if a path is a valid file, directory, not found, or permission denied.
- **render_json, render_csv, render_text**: Functions to render audit results in different formats.
- **parse_mode**: Parse permission strings (octal or symbolic) into numeric modes for auditing.

#### Example
```rust
use alhalo::{AuditRule, Importance, render_json};
let (rule, status) = AuditRule::new("/etc/passwd".into(), 0o644, Importance::Medium);
let mut visited = std::collections::HashSet::new();
let results = rule.check(&mut visited);
println!("{}", render_json(&results)?);
```

## Contributing
Contributions are welcome! Please open issues or pull requests for bugs, features, or improvements. 
Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for more information and the process of contributing to this project

## License
MIT

## Maintainers
- Aletha Labs

---
For more details, see the [crate documentation](https://docs.rs/alhalo) or run `--help` in the CLI.
