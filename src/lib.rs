//! # Aletha Labs: HALO — Linux System Permissions Audit
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
//!
//! ## Quick Start
//! Run the CLI:
//! ```bash
//! halo check --target user
//! halo parse --file /proc/cpuinfo --format json
//! ```
//!
//! Use as a library:
//! ```rust
//! use alhalo::audit::audit_permissions::{AuditRule, Severity};
//! let rule = AuditRule::new("/etc/passwd", 0o644, Severity::Low);
//! // ...
//! ```
//!
//! ## Modules
//! - [`audit`](crate::audit): Audit logic and rules
//! - [`render_output`](crate::render_output): Output formatting
//! - [`cli`](crate::cli): CLI command parsing
//!
//! ## Re-exports
//! The crate root re-exports key types and functions for convenience:
//! - `AuditRule`, `AuditPermissions`, `AuditError`, `Severity`, `Status`
//! - `AuditConfig`, `AuditRuleConfig`, `load_toml_rules`
//! - `OwnershipRule`, `OwnershipResult`, `check_ownership`
//! - `render_json`, `render_csv`, `render_text`, `filter`
//! - `Cli` (for CLI integration)
//!
//! ## More Info
//! - [GitHub](https://github.com/AlethaLabs/alhalo)
//! - [Crates.io](https://crates.io/crates/alhalo)
//! - [Docs.rs](https://docs.rs/alhalo)
//! - [Full CLI Usage](https://github.com/AlethaLabs/alhalo#usage)
//!
//! ---
//!
//! _MIT License_

pub mod audit;
pub mod cli;
pub mod handle_args;
pub mod macros;
pub mod render_output;

pub use audit::{
    audit_permissions::{
        AuditError, AuditPermissions, AuditRule, Importance, PermissionResults, Severity, Status,
        parse_mode,
    },
    default_permissions::{Log, NetConf, SysConfig, UserConfig},
    ownership::{OwnershipResult, OwnershipRule, check_ownership},
    toml_config::{AuditConfig, AuditRuleConfig, load_toml_rules},
};

pub use cli::Cli;
pub use handle_args::{
    AuditTarget, DataList, DataMap, handle_bash, handle_file, handle_ownership, handle_permissions,
    handle_summary,
};
pub use render_output::{filter, render_csv, render_json, render_text};
