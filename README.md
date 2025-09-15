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
- CLI and library APIs
- Output in JSON, CSV, and pretty text formats (JSON only for permission/ownership audits)

## Installation From Repo
This is a rust program, so rust is required to build the library.
If you need help with installing rust check out the - [Rust Installation Guide](https://www.rust-lang.org/tools/install)

You will also need to have git installed, to be sure type into your terminal:
```bash
git --version
```
After rust is installed and you confirmed your git installation, you can clone this repository
```bash
mkdir halo_build
cd halo_build
git clone https://github.com/AlethaLabs/HALO.git
```
Then build with rusts package manager/build tool - Cargo:
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
./target/release/halo check --path /etc/shadow --expect 640 --importance high 

# Audit file ownership (UID/GID)
./target/release/halo check --path /etc/shadow --expect-uid 0 --expect-gid 42 

# Load custom audit rules from TOML
./target/release/halo check --toml config.toml

# Generate Bash completion script
./target/release/halo bash --out halo.bash
source halo.bash
```
### Run examples
```bash
./target/release/halo check --toml /examples/toml_configs/permissions_config.toml
cargo run --example permissions
```
### Library
Add to your Rust project and use the API:
```bash
cargo add alhalo
```
```rust
use alhalo::{UserConfig, render_json};
let results = UserConfig::default().run_audit_perms();
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
For more details, see the crate documentation or run `help` in the CLI.
