//! TOML configuration loader for HALO audit rules.
//!
//! This module provides types and functions for parsing audit rules from TOML files for both permission and ownership audits.
//!
//! Features:
//! - Deserialize permission and ownership rule configs from TOML
//! - Validate and convert permission formats (octal, symbolic)
//! - Integrate with HALO's permission and ownership audit systems
//! - Supports custom audit configurations via config files
//!
//! # Example TOML
//! ```toml
//! [[perm_rules]]
//! path = "/etc/passwd"
//! expected_mode = 600 # or "0o600" or "u=rw,g=r,o="
//! importance = "Medium"
//! recursive = false
//!
//! [[owner_rules]]
//! path = "/etc/passwd"
//! expected_uid = 0
//! expected_gid = 0
//! ```
use crate::{
    Importance, OwnershipResult, OwnershipRule, PermissionResults, PermissionRules, parse_mode,
};
use serde::Deserialize;
use std::path::PathBuf;

/// Represents a single permission audit rule loaded from a TOML config file.
///
/// Fields:
/// - `path`: Path to the file or directory to audit permissions.
/// - `expected_mode`: Expected file mode (permissions) in octal, symbolic, or integer format.
/// - `importance`: Importance level for the permission rule.
/// - `recursive`: If true, audit directories recursively. Optional; defaults to false.
#[derive(Debug, Deserialize)]
pub struct PermissionConfig {
    pub path: String,
    /// Accepts either decimal (e.g. 644), octal string (e.g. "0o644"), or integer (e.g. 644)
    pub expected_mode: ModeValue,
    pub importance: Importance,
    pub recursive: Option<bool>,
}
// ...existing code...
// ...existing code...

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ModeValue {
    Int(u32),
    Str(String),
    // ...existing code...
}

/// Represents a single ownership audit rule loaded from a TOML config file.
///
/// Fields:
/// - `path`: Path to the file or directory to audit ownership.
/// - `expected_uid`: Optional expected UID for ownership audit.
/// - `expected_gid`: Optional expected GID for ownership audit.
/// - `follow_symlinks`: If true, follow symlinks (optional, default false)
/// - `recursive`: If true, audit directories recursively (optional, default false)
#[derive(Debug, Deserialize)]
pub struct OwnerConfig {
    pub path: String,
    pub expected_uid: Option<u32>,
    pub expected_gid: Option<u32>,
    pub follow_symlinks: Option<bool>,
    pub recursive: Option<bool>,
}

/// Represents the top-level TOML config structure for audit rules.
///
/// Fields:
/// - `perm_rules`: List of permission audit rules to apply.
/// - `owner_rules`: List of ownership audit rules to apply.
#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    pub perm_rules: Vec<PermissionConfig>,
    pub owner_rules: Vec<OwnerConfig>,
}

/// Loads rules for permission audits from a TOML configuration file.
///
/// # Arguments
/// * `path` - Path to the TOML file containing rules.
///
/// # Returns
/// * `Ok(Vec<PermissionResults>)` if parsing succeeds.
/// * `Err` with a user-friendly error message if reading or parsing fails, or if a rule is invalid.
///
/// # Example TOML
/// ```toml
/// [[perm_rules]]
/// path = "/etc/passwd"
/// expected_mode = 600 # or "0o600" or "u=rw,g=r,o="
/// importance = "Medium"
/// recursive = false
/// ```
pub fn toml_permissions(path: &str) -> Result<Vec<PermissionResults>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read TOML file '{}': {}", path, e))?;
    let config: AuditConfig =
        toml::from_str(&content).map_err(|e| format!("Failed to parse TOML config: {}", e))?;
    let mut results = Vec::new();

    // Process permission rules
    for rule in &config.perm_rules {
        // Validate path is non-empty and not just whitespace
        if rule.path.trim().is_empty() {
            return Err(format!("Audit rule has empty or invalid path.").into());
        }
        // Check if path exists
        let path_obj = PathBuf::from(&rule.path);
        if !path_obj.exists() {
            return Err(format!("Audit rule path '{}' does not exist.", rule.path).into());
        }
        let mode = match &rule.expected_mode {
            ModeValue::Int(i) => {
                let mode_str = i.to_string();
                match parse_mode(&mode_str) {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(format!(
                            "Invalid expected_mode '{}' for path '{}': {}",
                            i, rule.path, e
                        )
                        .into());
                    }
                }
            }
            ModeValue::Str(s) => match parse_mode(&s) {
                Ok(m) => m,
                Err(e) => {
                    return Err(format!(
                        "Invalid expected_mode '{}' for path '{}': {}",
                        s, rule.path, e
                    )
                    .into());
                }
            },
        };
        if mode > 0o777 {
            return Err(format!(
                "Invalid expected_mode {:o} for path '{}'. Must be <= 777.",
                mode, rule.path
            )
            .into());
        }
        // Clone importance to avoid lifetime shennanigans
        let importance = rule.importance.clone();
        let (mut audit_rule, _path_status) =
            PermissionRules::new(path_obj.clone(), mode, importance.clone());
        if let Some(rec) = rule.recursive {
            audit_rule.recursive = rec;
        }
        let mut visited = std::collections::HashSet::new();
        results.extend(audit_rule.check(&mut visited));
    }
    Ok(results)
}

/// Loads rules for ownership audits from a TOML configuration file.
///
/// # Arguments
/// * `path` - Path to the TOML file containing rules.
///
/// # Returns
/// * `Ok(Vec<OwnershipResult>)` if parsing succeeds.
/// * `Err` with a user-friendly error message if reading or parsing fails, or if a rule is invalid.
///
/// # Example TOML
/// ```toml
/// [[owner_rules]]
/// path = "/etc/passwd"
/// expected_uid = 0
/// expected_gid = 0
/// ```
pub fn toml_ownership(path: &str) -> Result<Vec<OwnershipResult>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read TOML file '{}': {}", path, e))?;
    let config: AuditConfig =
        toml::from_str(&content).map_err(|e| format!("Failed to parse TOML config: {}", e))?;
    let mut results = Vec::new();

    for owner in &config.owner_rules {
        // Validate path
        if owner.path.trim().is_empty() {
            return Err(format!("Ownership rule has empty or invalid path.").into());
        }
        let path_obj = PathBuf::from(&owner.path);
        if !path_obj.exists() {
            return Err(format!("Ownership rule path '{}' does not exist.", owner.path).into());
        }
        // Use 0 (root) as default if not specified, or skip if you prefer
        let expected_uid = owner.expected_uid.unwrap_or(0);
        let expected_gid = owner.expected_gid.unwrap_or(0);
        let follow_symlinks = owner.follow_symlinks.unwrap_or(false);
        let (mut ownership_rule, _path_status) =
            OwnershipRule::new(path_obj, expected_uid, expected_gid, follow_symlinks);
        if let Some(rec) = owner.recursive {
            ownership_rule.recursive = rec;
        }
        let ownership_result = ownership_rule.check_ownership();
        results.push(ownership_result);
    }
    Ok(results)
}

/*
* I would like to add YAML support in the future, but for now TOML is sufficient.
* The deprecation of serde_yaml is concerning and I would prefer to avoid adding
* dependencies that are unmaintained, maybe rust-yaml2 could be an alternative.
*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_toml(path: &std::path::Path, toml: &str) {
        let mut file = File::create(path).unwrap();
        file.write_all(toml.as_bytes()).unwrap();
    }

    #[test]
    fn test_valid_octal_mode() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("testfile");
        File::create(&file_path).unwrap();
        let toml = format!(
            r#"
            [[rules]]
            path = "{}"
            expected_mode = 644
            importance = "Medium"
        "#,
            file_path.display()
        );
        let toml_path = dir.path().join("config.toml");
        write_toml(&toml_path, &toml);
        let rules = toml_permissions(toml_path.to_str().unwrap());
        assert!(rules.is_ok());
        assert_eq!(rules.unwrap()[0].expected_mode, 0o644);
    }

    #[test]
    fn test_valid_symbolic_mode() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("testfile");
        File::create(&file_path).unwrap();
        let toml = format!(
            r#"
            [[rules]]
            path = "{}"
            expected_mode = "u=rw,g=r,o="
            importance = "High"
        "#,
            file_path.display()
        );
        let toml_path = dir.path().join("config.toml");
        write_toml(&toml_path, &toml);
        let rules = toml_permissions(toml_path.to_str().unwrap());
        assert!(rules.is_ok());
        assert_eq!(rules.unwrap()[0].expected_mode, 0o640);
    }

    #[test]
    fn test_invalid_mode_format() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("testfile");
        File::create(&file_path).unwrap();
        let toml = format!(
            r#"
            [[rules]]
            path = "{}"
            expected_mode = "notamode"
            importance = "Low"
        "#,
            file_path.display()
        );
        let toml_path = dir.path().join("config.toml");
        write_toml(&toml_path, &toml);
        let rules = toml_permissions(toml_path.to_str().unwrap());
        assert!(rules.is_err());
    }

    #[test]
    fn test_nonexistent_path() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("doesnotexist");
        let toml = format!(
            r#"
            [[rules]]
            path = "{}"
            expected_mode = 600
            importance = "Medium"
        "#,
            file_path.display()
        );
        let toml_path = dir.path().join("config.toml");
        write_toml(&toml_path, &toml);
        let rules = toml_permissions(toml_path.to_str().unwrap());
        assert!(rules.is_err());
    }

    #[test]
    fn test_empty_path() {
        let dir = tempdir().unwrap();
        let toml = r#"
            [[rules]]
            path = "   "
            expected_mode = 600
            importance = "Low"
        "#;
        let toml_path = dir.path().join("config.toml");
        write_toml(&toml_path, toml);
        let rules = toml_permissions(toml_path.to_str().unwrap());
        assert!(rules.is_err());
    }
    // ...existing code...
}
