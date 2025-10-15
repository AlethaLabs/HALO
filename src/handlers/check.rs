use crate::fix_script::generate_fix_script;
use alhalo::{
    AuditPermissions, Importance, Log, NetConf, PermissionRules, SysConfig, UserConfig,
    toml_ownership, toml_permissions, Renderable, parse_mode,
};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

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

// Audits file permissions and/or ownership based on CLI arguments.
// Supports permission checks, ownership checks, and TOML config loading.
// Results are rendered and printed in the selected format.
pub fn handle_check(
    target: &Option<AuditTarget>,
    path: &Option<PathBuf>,
    format: &Option<String>,
    expect: &Option<String>,
    importance: &Option<Importance>,
    expect_uid: &Option<u32>,
    expect_gid: &Option<u32>,
    store: &Option<PathBuf>,
    toml: &Option<PathBuf>,
) {
    if toml.is_some() {
        handle_toml();
        return;
    }
    let permission_args = target.is_some() || (expect.is_some() && importance.is_some());
    let ownership_args = expect_uid.is_some() || expect_gid.is_some();

    if permission_args && ownership_args {
        let parsed_mode = expect.as_ref().map(|s| parse_mode(s)).transpose();
        match parsed_mode {
            Ok(mode_opt) => {
                handle_permissions(
                    target.as_ref().map(|t| t.to_owned()),
                    path.as_ref().map(|p| p.to_owned()),
                    mode_opt,
                    importance.as_ref().map(|i| i.to_owned()),
                    store.as_ref().map(|s| s.to_owned()),
                    format,
                );
            }
            Err(e) => eprintln!("Error parsing expected mode: {}", e),
        }
        handle_ownership(
            path.as_ref().map(|p| p.to_owned()),
            *expect_uid,
            *expect_gid,
            format,
        );
    } else if permission_args {
        let parsed_mode = expect.as_ref().map(|s| parse_mode(s)).transpose();
        match parsed_mode {
            Ok(mode_opt) => {
                handle_permissions(
                    target.as_ref().map(|t| t.to_owned()),
                    path.as_ref().map(|p| p.to_owned()),
                    mode_opt,
                    importance.as_ref().map(|i| i.to_owned()),
                    store.as_ref().map(|s| s.to_owned()),
                    format,
                );
            }
            Err(e) => eprintln!("Error parsing expected mode: {}", e),
        }
    } else if ownership_args {
        handle_ownership(
            path.as_ref().map(|p| p.to_owned()),
            *expect_uid,
            *expect_gid,
            format,
        );
    } else {
        println!("No valid permission or ownership audit arguments provided.\n");
    }
}

// Audits file permissions based on target type or custom path/mode
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

// Handler for ownership auditing
//
// Checks the ownership of a given path against expected UID and GID.
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

// Handler for TOML configuration loading
//
// Loads and processes TOML configuration files for permissions and ownership audits
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