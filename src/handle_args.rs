use crate::cli::Cli;
use crate::{
    AuditPermissions, AuditRule, Importance, Log, NetConf, PermissionResults, SysConfig,
    UserConfig, render, render_json,
};
use clap::CommandFactory;
use indexmap::IndexMap;
use std::fs;
use std::path::PathBuf;

/// A deterministic map of key-value pairs parsed from a file.
///
/// Using `IndexMap` instead of `HashMap` avoids randomizing file contents, ensuring stable output order.
pub type DataMap = IndexMap<String, String>;

/// A list of parsed data maps, representing structured file contents.
pub type DataList = Vec<DataMap>;

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
) -> Vec<PermissionResults> {
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
                // Collect results into a temporary vector and then extend the main one.
                results.extend(UserConfig::default().run_audit_perms());
                results.extend(SysConfig::default().run_audit_perms());
                results.extend(NetConf::default().run_audit_perms());
                results.extend(Log::default().run_audit_perms());
            }
        }
    } else if let Some(p) = path {
        if let (Some(mode), Some(imp)) = (expected_mode, importance) {
            results.extend(AuditRule::custom_audit(p, mode, imp));
        } else {
            eprintln!("Error: Both --expect and --importance are required with --path.");
        }
    }
    // The final `results` vector is returned here, containing all the appended results.
    results
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
) -> Option<crate::audit::ownership::OwnershipResult> {
    if let Some(path_val) = path {
        if expect_uid.is_some() || expect_gid.is_some() {
            let rule = crate::audit::ownership::OwnershipRule {
                path: path_val,
                expected_uid: expect_uid.unwrap_or(0),
                expected_gid: expect_gid.unwrap_or(0),
            };
            return Some(crate::audit::ownership::check_ownership(&rule));
        }
    }
    None
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

/// Handles summary output for permission audit results.
/// Prints summary statistics and details for failed results.
///
/// # Arguments
/// * `results` - Slice of PermissionResults to summarize
/// * `store` - Optional path to store JSON output
/// * `format` - Output format (Some("json"), "pretty", etc)
pub fn handle_summary(
    results: &[crate::PermissionResults],
    store: Option<std::path::PathBuf>,
    format: &Option<String>,
) {
    let total = results.len();
    let failed: Vec<_> = results
        .iter()
        .filter(|r| r.status == crate::Status::Fail)
        .collect();
    let passed = results
        .iter()
        .filter(|r| r.status == crate::Status::Pass)
        .count();
    let strict = results
        .iter()
        .filter(|r| r.status == crate::Status::Strict)
        .count();

    match render!(&results, format) {
        Ok(output) => {
            print!("{}", output);
            if let Some(path) = store {
                // Only store JSON output
                if format.as_deref() == Some("json") {
                    if let Err(e) = std::fs::write(&path, &output) {
                        eprintln!("Failed to store output: {}", e);
                    } else {
                        println!("JSON output stored to {}", path.display());
                    }
                } else {
                    println!("Store is only supported for JSON output. Use --format json.");
                }
            }
            println!(
                "\nSummary: {} checked, {} passed, {} strict, {} failed",
                total,
                passed,
                strict,
                failed.len()
            );
            for r in failed {
                println!(
                    "[!] FAIL: {} (found: {:o}, expected: {:o})",
                    r.path.display(),
                    r.found_mode,
                    r.expected_mode
                );
                // Suggest chmod if path is file and expected_mode is not 0
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
        }
        Err(e) => eprintln!("Error rendering output: {}", e),
    }
}
