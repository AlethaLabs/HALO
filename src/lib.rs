//! Aletha Labs: HALO: Host Armor for Linux Operations - A Linux System Permissions Audit Library and CLI
//!
//! This crate provides tools for auditing, parsing, and rendering Linux system configuration and permissions.
//! It is designed for both home users and sysadmins, with a focus on extensibility and actionable output.
//!
//! Main features:
//! - Audit system/user/network/log files for best-practice permissions
//! - Configurable rules via TOML
//! - CLI and library APIs
//! - Output in JSON, CSV, and pretty text formats
//!
//! See the CLI help or crate documentation for usage examples.

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
