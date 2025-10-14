//! CLI argument handlers and audit dispatch for HALO.
//!
//! This module provides:
//! - File parsing utilities for structured data
//! - Audit target selection and permission checks
//! - Ownership and summary handlers for CLI output
//!
//! Used by the main CLI loop to process commands and render results for users and sysadmins.
use crate::cli::Cli;
use crate::fix_script::generate_fix_script;
use alhalo::audit::networking::discovery::{get_arp_devices};
use alhalo::{
    AuditPermissions, Importance, Log, NetConf, PermissionRules, SysConfig, UserConfig,
    toml_ownership, toml_permissions, Renderable,
};
use clap::CommandFactory;
use indexmap::IndexMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

/// A deterministic map of key-value pairs parsed from a file.
///
/// Using `IndexMap` instead of `HashMap` avoids randomizing file contents, ensuring stable output order.
type DataMap = IndexMap<String, String>;

/// A list of parsed data maps, representing structured file contents.
type DataList = Vec<DataMap>;

/// Audit targets for permissions check.
///
/// Used to select which group of files to audit for permissions.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum AuditTarget {
    User,
    Sys,
    Net,
    Log,
    All,
}

/// Parses a file into a list of key-value maps.
///
/// Each non-empty line containing a colon is split into key and value, trimmed, and added to the current map.
/// Blank lines separate records. Returns a list of maps for each record.
///
/// # Arguments
/// * `file` - Optional path to the file to parse. If `None`, returns an empty list.
pub fn handle_file(file: Option<PathBuf>) -> DataList {
    // println!("DEBUG: trying to read {:?}", paths);
    let content = if let Some(path) = file {
        fs::read_to_string(path)
    } else {
        Ok(String::new())
    };

    let mut data: DataList = Vec::new();
    let mut current_map: DataMap = IndexMap::new();

    for line in content.unwrap_or_default().lines() {
        if line.trim().is_empty() {
            if !current_map.is_empty() {
                data.push(current_map.clone());
                current_map.clear();
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            current_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    if !current_map.is_empty() {
        data.push(current_map);
    }

    data
}

/// Handles permission audit requests from the CLI.
///
/// Dispatches to built-in audit targets or custom file audits based on arguments.
///
/// # Arguments
/// * `target` - Optional predefined audit target (User, Sys, Net, Log, All).
/// * `path` - Optional custom file or directory path to audit.
/// * `expected_mode` - Expected file mode (octal).
/// * `importance` - Importance level for the audit.
///
/// Returns a vector of `PermissionResults` for all audited files.
pub fn handle_permissions(
    target: Option<AuditTarget>,
    path: Option<PathBuf>,
    expected_mode: Option<u32>,
    importance: Option<Importance>,
    store: Option<PathBuf>,
    format: &Option<String>,
) {
    let mut results = Vec::new();

    if let Some(t) = target {
        match t {
            AuditTarget::User => {
                let user = UserConfig::default();
                results.extend(user.run_audit_perms());
            }
            AuditTarget::Sys => {
                let sys = SysConfig::default();
                results.extend(sys.run_audit_perms());
            }
            AuditTarget::Net => {
                let net = NetConf::default();
                results.extend(net.run_audit_perms());
            }
            AuditTarget::Log => {
                let logs = Log::default();
                results.extend(logs.run_audit_perms());
            }
            AuditTarget::All => {
                results.extend(UserConfig::default().run_audit_perms());
                results.extend(SysConfig::default().run_audit_perms());
                results.extend(NetConf::default().run_audit_perms());
                results.extend(Log::default().run_audit_perms());
            }
        }
    } else if let Some(p) = path {
        if let (Some(mode), Some(imp)) = (expected_mode, importance) {
            results.extend(PermissionRules::custom_audit(p, mode, imp));
        } else {
            eprintln!("Error: Both --expect and --importance are required with --path.");
        }
    }

    // Handle output rendering
    if format.is_some() {
        // Use trait-based rendering for specified formats
        results.render_and_print(format.as_deref());
        
        // Handle file storage for JSON format
        if format.as_deref() == Some("json") {
            if let Some(ref path) = store {
                if let Ok(output) = results.render(alhalo::render_output::OutputFormat::Json) {
                    if let Err(e) = std::fs::write(&path, &output) {
                        eprintln!("Failed to store output: {}", e);
                    } else {
                        println!("JSON output stored to {}", path.display());
                    }
                }
            }
        }
    }

    // Print summary and suggested fixes
    let total = results.len();
    let failed: Vec<_> = results
        .iter()
        .filter(|r| r.status == alhalo::Status::Fail)
        .collect();
    let passed = results
        .iter()
        .filter(|r| r.status == alhalo::Status::Pass)
        .count();
    let strict = results
        .iter()
        .filter(|r| r.status == alhalo::Status::Strict)
        .count();
    println!(
        "\nSummary: {} checked, {} passed, {} strict, {} failed",
        total,
        passed,
        strict,
        failed.len()
    );
    for r in &failed {
        println!(
            "[!] FAIL: {} (found: {:o}, expected: {:o})",
            r.path.display(),
            r.found_mode,
            r.expected_mode
        );
        if r.found_mode != r.expected_mode && r.path.is_file() && r.expected_mode != 0 {
            println!(
                "    Suggested fix: # chmod {:o} {}",
                r.expected_mode,
                r.path.display()
            );
        }
        if let Some(err) = &r.error {
            println!("    Error: {}", err);
        }
    }
    // If any permissions failed, generate script to fix permissions
    if !failed.is_empty() {
        print!("Would you like to apply the suggested fixes? [y/N]: ");
        io::stdout().flush().ok();
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_ok() {
            if answer.trim().eq_ignore_ascii_case("y") {
                let script = generate_fix_script(&results);
                println!("\n --- Permission Fix Generated --- \n{}\n", script);
                print!("Run suggested fixes? [y/N]: ");
                io::stdout().flush().ok();
                let mut run_answer = String::new();
                if io::stdin().read_line(&mut run_answer).is_ok() {
                    if run_answer.trim().eq_ignore_ascii_case("y") {
                        let tmp_path = "/tmp/fix_permissions.sh";
                        if let Err(e) = std::fs::write(tmp_path, &script) {
                            eprintln!("Failed to write script: {}", e);
                        } else {
                            println!("Running fix script as root (requires sudo)...");
                            let status = std::process::Command::new("sudo")
                                .arg("bash")
                                .arg(tmp_path)
                                .status();
                            match status {
                                Ok(s) if s.success() => println!("Permissions fixed"),
                                Ok(s) => eprintln!("Script exited with: {}", s),
                                Err(e) => eprintln!("Failed to run script: {}", e),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Handles ownership audit requests from the CLI.
///
/// Checks the ownership of a given path against expected UID and GID.
/// Returns the audit result struct.
///
/// # Arguments
/// * `path` - Path to the file or directory to check
/// * `expect_uid` - Expected UID (user ID)
/// * `expect_gid` - Expected GID (group ID)
///
/// Returns an OwnershipResult (see audit/ownership.rs)
pub fn handle_ownership(
    path: Option<PathBuf>,
    expect_uid: Option<u32>,
    expect_gid: Option<u32>,
    format: &Option<String>,
) {
    if let Some(path_val) = path {
        if expect_uid.is_some() || expect_gid.is_some() {
            let (rule, _status) = alhalo::OwnershipRule::new(
                path_val,
                expect_uid.unwrap_or(0),
                expect_gid.unwrap_or(0),
                true,
            );
            let result = rule.check_ownership();
            result.render_and_print(format.as_deref());
            // Optionally, print summary or suggested fixes here if desired
            return;
        }
    }
    println!("Ownership check could not be performed.");
}

/// Handler for Bash completion script generation
pub fn handle_bash(out: &str) {
    use clap_complete::{generate_to, shells::Bash};
    use std::path::Path;
    let mut cmd = Cli::command();
    match generate_to(
        Bash,
        &mut cmd,
        "halo",
        Path::new(out).parent().unwrap_or_else(|| Path::new(".")),
    ) {
        Ok(path) => {
            println!("Bash completion script generated at: {}", path.display())
        }
        Err(e) => eprintln!("Failed to generate completion script: {}", e),
    }
}

pub fn handle_toml() {
    // Get TOML file path and format from CLI args (simple version: env vars or prompt)
    let args: Vec<String> = env::args().collect();
    let toml_path = args.iter().find(|a| a.ends_with(".toml"));
    let format = args.iter().find(|a| a == &"--format").and_then(|_| {
        let idx = args.iter().position(|a| a == "--format");
        idx.and_then(|i| args.get(i + 1))
    });

    let format = format.map(|s| s.to_string()).or(Some("json".to_string()));

    if let Some(path_str) = toml_path {
        // Permissions
        match toml_permissions(path_str) {
            Ok(toml_permission_results) => {
                toml_permission_results.render_and_print(format.as_deref());
            },
            Err(e) => eprintln!("Error loading TOML permission rules: {}", e),
        }
        // Ownership
        match toml_ownership(path_str) {
            Ok(toml_owner_results) => {
                if !toml_owner_results.is_empty() {
                    toml_owner_results.render_and_print(format.as_deref());
                }
            },
            Err(e) => eprintln!("Error loading TOML ownership rules: {}", e),
        }
    } else {
        eprintln!(
            "No TOML file path provided. Usage: halo check --toml config.toml [--format json|csv|text]"
        );
    }
}

/// Handle Networking
pub fn handle_net(format: &Option<String>, devices: bool) {
    if devices {
        match get_arp_devices() {
            Ok(results) => {
                results.render_and_print(format.as_deref());
            },
            Err(e) => eprintln!("Error discovering network devices: {}", e),
        }
    } else {
        eprintln!("Network discovery requires the --devices flag");
    }
}
