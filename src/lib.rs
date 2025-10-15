#![doc(html_root_url = "https://docs.rs/alhalo")]
//! # Aletha Labs: HALO — Host Armor for Linux Operations
//!
//! **Audit, parse, and render Linux system configuration and permissions.**
//!
//! ---
//!
//! ## Overview
//! Aletha Labs: HALO - `alhalo` is a CLI tool and Rust library for auditing Linux system, user, network, and log file permissions. Designed for home users and sysadmins, it provides actionable, extensible, and configurable output.
//!
//! ## Features
//! - Audit system, user, network, and log files for best-practice permissions
//! - Configurable audit rules via TOML
//! - Built-in and custom audit targets
//! - Output in pretty text, JSON, or CSV
//! - CLI and library APIs
//! - Ownership audit for files and directories
//! - Symlink audit: check symlink existence and target
//! - Easy integration into scripts and automation
//! - Open source under the MIT License
//! - Actively maintained by Aletha Labs
//!
//! ## Library Usage:
//! This is a new library, there is bound to be some rough edges and breaking changes.
//! Please open issues or PRs on [GitHub](https://github.com/AlethaLabs/halo) if you have suggestions or find bugs.
//! Starting Friday - 2025-9-19 - there will be minor-major releases once per month.
//! 
//! ### Simple Usage (Recommended)
//! ```rust
//! use alhalo::prelude::*;
//! use std::collections::HashSet;
//!
//! fn main() {
//!     // Create an audit rule for /etc/passwd with expected mode 0o644 and medium importance
//!     let (rule, status) = PermissionRules::new("/etc/passwd".into(), 0o644, Importance::Medium);
//!
//!     // Run the audit (checks permissions and returns results)
//!     let mut visited = HashSet::new();
//!     let results: Vec<PermissionResults> = rule.check(&mut visited);
//!
//!     // Handle the case where the path does not exist
//!     match status {
//!         PathStatus::NotFound => {
//!             eprintln!("Warning: Path {} not found", rule.path.display());
//!             return;
//!         }
//!         _ => {
//!             // Print the results using trait-based rendering
//!             results.render_and_print(Some("json"));
//!         }
//!     }
//! }
//! ```
//! 
//! ### Alternative Usage (Explicit Imports)
//! ```rust
//! use alhalo::{PermissionRules, Importance, PermissionResults, check_symlink, SymRule};
//! use alhalo::render_output::{Renderable, OutputFormat};
//! use std::collections::HashSet;
//!
//! fn main() {
//!     // Same code as above...
//!
//!     // Symlink audit example
//!     let sym_rule = SymRule {
//!         path: "/etc/ssl/certs/ca-certificates.crt".into(),
//!         target_link: None, // Optionally set expected target
//!     };
//!     let sym_result = check_symlink(&sym_rule);
//!     println!("Symlink target: {:?}, Pass: {}", sym_result.target, sym_result.pass);
//! }
//! ```
//! Expected output:
//! ```bash
//! [
//!  {
//!    "severity": "None",
//!    "status": "Pass",
//!    "path": "/etc/passwd",
//!    "expected_mode": "644",
//!    "found_mode": "644",
//!    "importance": "Medium"
//!  }
//!]
//! ```
//!
//! ## Quick Start
//! See [Github](https://github.com/AlethaLabs/halo) to build CLIfrom source
//! ```bash
//! cargo run
//! Welcome to Aletha Labs: HALO - Host Armor for Linux Operations
//!
//! Please enter your commands, or type 'help' for further information
//! halo> check --target user
//! [
//!  {
//!    "severity": "None",
//!    "status": "Pass",
//!    "path": "/etc/passwd",
//!    "expected_mode": "644",
//!    "found_mode": "644",
//!    "importance": "Medium"
//!  },
//!  { .....
//!
//! Summary: 29 checked, 27 passed, 0 strict, 2 failed
//! [!] FAIL: /etc/shadow (found: 640, expected: 600)
//!     Suggested fix: chmod 600 /etc/shadow
//! .....
//! ```
//! Or run a single command directly:
//! ```bash
//! cargo run parse --file /proc/cpuinfo --format json
//! ```
//!
//! ## More Info
//! - [GitHub](https://github.com/AlethaLabs/halo)
//! - [Crates.io](https://crates.io/crates/alhalo)
//! - [Docs.rs](https://docs.rs/alhalo)
//!
//! ---
//!
//! _MIT License_

//! ## API Organization
//! 
//! - **Quick Start**: Use [`prelude`] for easy imports
//! - **Core Types**: [`PermissionRules`], [`PermissionResults`], [`Importance`] 
//! - **Rendering**: [`Renderable`] trait for output formatting
//! - **Advanced**: Full API available through submodules ([`audit`], [`render_output`])

pub mod audit;
pub mod macros;
pub mod render_output;
pub mod prelude;

#[doc(hidden)]
pub use audit::{
    permissions::{
        audit_permissions::{
            AuditPermissions, Severity, PathStatus, Status, AuditError,
            parse_mode, perm_to_datalist, PermissionResults, PermissionRules, Importance,
        },
        default_permissions::{Log, NetConf, SysConfig, UserConfig},
    },
    ownership::ownership::{OwnershipResult, OwnershipRule, ownership_to_datalist},
    symlink::{SymResult, SymRule, check_symlink},
    toml_config::{AuditConfig, OwnerConfig, PermissionConfig, toml_ownership, toml_permissions},
    networking::discovery,
};

#[doc(hidden)]
pub use render_output::{Renderable, OutputFormat, DataList, DataMap, filter, render_csv, render_json, render_text, ParsedData};
