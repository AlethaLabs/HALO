//! TOML configuration loader for HALO audit rules.
//!
//! This module provides types and functions for parsing audit rules from TOML files.
//!
//! Features:
//! - Deserialize audit rule configs from TOML
//! - Validate and convert permission formats (octal, symbolic)
//! - Integrate with HALO's permission audit system
//!
//! Used to support custom audit configurations via CLI or config files.
use crate::audit::audit_permissions::parse_mode;
use crate::{AuditRule, Importance};
use serde::Deserialize;
use std::path::PathBuf;

/// Represents a single audit rule loaded from a TOML config file.
///
/// Fields:
/// - `path`: Path to the file or directory to audit.
/// - `expected_mode`: Expected file mode (permissions) in octal (e.g., 644).
/// - `importance`: Importance level for the audit rule.
/// - `recursive`: If true, audit directories recursively. Optional; defaults to false.
#[derive(Debug, Deserialize)]
pub struct AuditRuleConfig {
    pub path: String,
    /// Accepts either decimal (e.g. 644), octal string (e.g. "0o644"), or integer (e.g. 644)
    pub expected_mode: ModeValue,
    pub importance: Importance,
    pub recursive: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ModeValue {
    Int(u32),
    Str(String),
}

/// Represents the top-level TOML config structure for audit rules.
///
/// Fields:
/// - `rules`: List of audit rules to apply.
#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    pub rules: Vec<AuditRuleConfig>,
}

/// Loads audit rules from a TOML configuration file.
///
/// # Arguments
/// * `path` - Path to the TOML file containing audit rules.
///
/// # Returns
/// * `Ok(Vec<AuditRule>)` if parsing succeeds.
/// * `Err` with a user-friendly error message if reading or parsing fails, or if a rule is invalid.
///
/// # Example TOML
/// ```toml
/// [[rules]]
/// path = "/etc/passwd"
/// expected_mode = 600 - or "0o600" or u=rw,g=r,o=
/// importance = "Medium"
/// recursive = false
/// ```
use crate::audit::audit_permissions::PermissionResults;

pub fn load_toml_rules(path: &str) -> Result<Vec<PermissionResults>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read TOML file '{}': {}", path, e))?;
    let config: AuditConfig =
        toml::from_str(&content).map_err(|e| format!("Failed to parse TOML config: {}", e))?;
    let mut results = Vec::new();
    for rule in &config.rules {
        // Validate path is non-empty and not just whitespace
        if rule.path.trim().is_empty() {
            return Err(format!("Audit rule has empty or invalid path.").into());
        }
        // Optionally, check if path exists on the filesystem
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
            ModeValue::Str(s) => match parse_mode(s) {
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

        // Clone importance to avoid lifetime issues
        let importance = rule.importance.clone();

        let (mut audit_rule, _path_status) = AuditRule::new(path_obj, mode, importance);
        // Override recursive if specified in TOML
        if let Some(rec) = rule.recursive {
            audit_rule.recursive = rec;
        }
        let mut visited = std::collections::HashSet::new();
        results.extend(audit_rule.check(&mut visited));
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
        let rules = load_toml_rules(toml_path.to_str().unwrap());
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
        let rules = load_toml_rules(toml_path.to_str().unwrap());
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
        let rules = load_toml_rules(toml_path.to_str().unwrap());
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
        let rules = load_toml_rules(toml_path.to_str().unwrap());
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
        let rules = load_toml_rules(toml_path.to_str().unwrap());
        assert!(rules.is_err());
    }
}
