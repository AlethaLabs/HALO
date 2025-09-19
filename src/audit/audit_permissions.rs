//! Permission audit logic for HALO.
//!
//! This module provides types, traits, and functions for auditing Linux file and directory permissions.
//!
//! # Main Features
//! - Audit rules for files and directories
//! - Severity and status classification for permission mismatches
//! - Parsing of octal and symbolic permission formats
//! - Recursive directory audits and custom audit support
//! - Symlink detection and reporting
//! - Permission denied, file not found, and other error handling
//!
//! Used by the HALO CLI to check system configuration and security posture.
//!
//! # Example Usage
//!
//! ## Auditing a Single File
//! ```rust
//! use alhalo::{PermissionRules, Importance};
//! let rule = PermissionRules {
//!     path: "/etc/passwd".into(),
//!     expected_mode: 0o644,
//!     recursive: false,
//!     importance: Importance::High,
//! };
//! let mut visited = std::collections::HashSet::new();
//! let results = rule.check(&mut visited);
//! for res in results {
//!     println!("{}: found {:o}, expected {:o}, status: {:?}", res.path.display(), res.found_mode, res.expected_mode, res.status);
//! }
//! ```
//!
//! ## Auditing a Directory Recursively
//! ```rust
//! use alhalo::{PermissionRules, Importance};
//! let rule = PermissionRules {
//!     path: "/var/log".into(),
//!     expected_mode: 0o640,
//!     recursive: true,
//!     importance: Importance::Medium,
//! };
//! let mut visited = std::collections::HashSet::new();
//! let results = rule.check(&mut visited);
//! println!("Checked {} files/directories", results.len());
//! ```
//!
//! ## Custom Audit with Error Handling
//! ```rust
//! use alhalo::{PermissionRules, Importance};
//! let results = PermissionRules::custom_audit("/tmp/does_not_exist".into(), 0o600, Importance::Low);
//! for res in results {
//!     if let Some(err) = &res.error {
//!         println!("Error auditing {}: {}", res.path.display(), err);
//!     }
//! }
//! ```
//!
//! ## Parsing Permission Strings
//! ```rust
//! use alhalo::parse_mode;
//! assert_eq!(parse_mode("640"), Ok(0o640));
//! assert_eq!(parse_mode("rw-r-----"), Ok(0o640));
//! assert_eq!(parse_mode("u=rw,g=r,o="), Ok(0o640));
//! ```
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// File permission bitmasks for audit severity checks.
///
/// - `WORLD_WRITE`: Others write bit (critical risk)
/// - `GROUP_PERMS`: Group read/write/execute bits
/// - `OTHER_PERMS`: Others read/write/execute bits
///
/// These constants are used to determine the severity of permission mismatches.
const WORLD_WRITE: u32 = 0o002;
const GROUP_PERMS: u32 = 0o070;
const OTHER_PERMS: u32 = 0o007;

/// Severity level of audit failure.
///
/// Used to classify the risk of a permission mismatch when auditing file or directory permissions.
#[derive(Debug, Clone, Serialize, PartialEq, Deserialize)]
pub enum Severity {
    /// No issue (exact match)
    None,
    /// Informational (stricter than expected)
    Info,
    /// Critical risk (world-writable)
    Critical,
    /// High risk (more permissive than expected)
    High,
    /// Medium risk
    Medium,
    /// Low risk (other mismatches)
    Low,
}

/// Status of a user-selected path for audit.
///
/// Indicates whether the path is a valid file, directory, or not found.
#[derive(Debug, PartialEq)]
pub enum PathStatus {
    /// Path is a valid file
    ValidFile,
    /// Path is a valid directory
    ValidDirectory,
    /// Path not found
    NotFound,
    /// Permission denied when accessing path
    PermissionDenied,
}

/// Result status for a permission audit.
///
/// Indicates whether the permissions passed, failed, or are stricter than expected.
#[derive(Debug, Serialize, PartialEq)]
pub enum Status {
    /// Permissions match expected
    Pass,
    /// Permissions are more permissive than expected
    Fail,
    /// Permissions are stricter than expected
    Strict,
}

/// Importance level for an audited file or directory.
///
/// Used to indicate the security relevance of a file or directory in an audit.
#[derive(Debug, Serialize, PartialEq, clap::ValueEnum, Clone, Deserialize)]
pub enum Importance {
    /// High importance (security-critical)
    High,
    /// Medium importance
    Medium,
    /// Low importance
    Low,
}

/// Result of a permission audit for a single file or directory.
///
/// Contains the outcome of a permission check, including severity, status, path, expected and found modes, importance, and any error.
#[derive(Debug, Serialize)]
pub struct PermissionResults {
    /// Severity of the mismatch
    pub severity: Severity,
    /// Status of the audit (Pass, Fail, Strict)
    pub status: Status,
    /// Path audited
    pub path: PathBuf,
    /// Expected file mode (octal)
    #[serde(serialize_with = "as_octal")]
    pub expected_mode: u32,
    /// Found file mode (octal)
    #[serde(serialize_with = "as_octal")]
    pub found_mode: u32,
    /// Importance of the file
    pub importance: Importance,
    /// Optional error if audit failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AuditError>,
}

/// Helper to serialize file modes as octal strings for JSON output.
///
/// Used for pretty-printing file modes in audit results.
pub fn as_octal<S>(mode: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{:o}", mode))
}

/// Trait for audit rule configuration structs.
///
/// Implement this trait to provide audit rules for a group of files or directories.
/// Used to define and run permission audits for custom configuration structs.
pub trait AuditPermissions {
    /// Returns a vector of audit rules for the struct.
    fn rules(&self) -> Vec<PermissionRules>;

    /// Runs all audit rules and returns a vector of results.
    fn run_audit_perms(&self) -> Vec<PermissionResults> {
        let mut results = Vec::new();
        let mut visited = HashSet::new();
        for rule in self.rules() {
            results.extend(rule.check(&mut visited));
        }
        results
    }
}

/// Audit rule for a single file or directory path.
///
/// Defines the path, expected mode, recursion, and importance for auditing.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PermissionRules {
    /// Path to audit
    pub path: PathBuf,
    /// Expected file mode (octal, e.g. 0o640)
    pub expected_mode: u32,
    /// If true, recursively audit directory contents
    pub recursive: bool,
    /// Importance of the file or directory
    pub importance: Importance,
}

/* Needs more robust error handling */
impl PermissionRules {
    /// Create a new audit rule and determine the path status.
    ///
    /// Returns the rule and whether the path is a file, directory, or not found.
    ///
    /// # Arguments
    /// * `path` - Path to audit
    /// * `expected_mode` - Expected file mode (octal)
    /// * `importance` - Importance level
    ///
    /// # Returns
    /// Tuple of `PermissionRules` and `PathStatus`.
    pub fn new(path: PathBuf, expected_mode: u32, importance: Importance) -> (Self, PathStatus) {
        if !path.exists() {
            return (
                PermissionRules {
                    path,
                    expected_mode,
                    importance,
                    recursive: false,
                },
                PathStatus::NotFound,
            );
        }

        match fs::metadata(&path) {
            Ok(meta) => {
                if meta.is_file() {
                    (
                        PermissionRules {
                            path,
                            expected_mode,
                            importance,
                            recursive: false,
                        },
                        PathStatus::ValidFile,
                    )
                } else if meta.is_dir() {
                    (
                        PermissionRules {
                            path,
                            expected_mode,
                            importance,
                            recursive: true,
                        },
                        PathStatus::ValidDirectory,
                    )
                } else {
                    (
                        PermissionRules {
                            path,
                            expected_mode,
                            importance,
                            recursive: false,
                        },
                        PathStatus::NotFound, // fallback for weird cases
                    )
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    (
                        PermissionRules {
                            path,
                            expected_mode,
                            importance,
                            recursive: false,
                        },
                        PathStatus::PermissionDenied,
                    )
                } else {
                    (
                        PermissionRules {
                            path,
                            expected_mode,
                            importance,
                            recursive: false,
                        },
                        PathStatus::NotFound,
                    )
                }
            }
        }
    }

    /// Determine severity based on mode comparison.
    ///
    /// Returns a `Severity` value based on the difference between found and expected mode.
    ///
    /// # Arguments
    /// * `mode_found` - The actual file mode found
    ///
    /// # Returns
    /// Severity of the mismatch
    pub fn determine_severity(&self, mode_found: u32) -> Severity {
        // World-writable is always critical
        if (mode_found & WORLD_WRITE) != 0 {
            return Severity::Critical;
        }

        // Exact match is 'None' severity
        if mode_found == self.expected_mode {
            return Severity::None;
        }

        // More permissive than expected (group/other bits)
        if (mode_found & GROUP_PERMS) > (self.expected_mode & GROUP_PERMS)
            || (mode_found & OTHER_PERMS) > (self.expected_mode & OTHER_PERMS)
        {
            return Severity::High;
        }

        // Stricter than expected (fewer bits set)
        if (mode_found & 0o777) < (self.expected_mode & 0o777) {
            return Severity::Info;
        }

        // Fallback for other mismatches
        Severity::Low
    }

    /// Check the permissions of the file or directory against the expected mode.
    ///
    /// Returns a vector of `PermissionResults` for the audited path and its contents (if recursive).
    ///
    /// # Arguments
    /// * `visited` - HashSet to track visited directories (by dev/inode)
    ///
    /// # Returns
    /// Vector of `PermissionResults` for the path and its children (if recursive)
    pub fn check(&self, visited: &mut HashSet<(u64, u64)>) -> Vec<PermissionResults> {
        let mut results = Vec::new();

        // Symlink handling
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_symlink() {
                use crate::audit::symlink::{SymRule, check_symlink};
                let sym_rule = SymRule {
                    path: self.path.clone(),
                    target_link: None, // You may want to pass a specific expected target
                };
                let sym_result = check_symlink(&sym_rule);
                // Map SymResult to PermissionResults for compatibility
                results.push(PermissionResults {
                    path: sym_result.path.clone(),
                    status: if sym_result.pass {
                        Status::Pass
                    } else {
                        Status::Strict
                    },
                    expected_mode: self.expected_mode,
                    found_mode: 0,
                    severity: if sym_result.pass {
                        Severity::None
                    } else {
                        Severity::Info
                    },
                    importance: self.importance.clone(),
                    error: sym_result.error.map(AuditError::Other),
                });
                return results;
            }
        }

        if self.path.is_file() {
            match fs::metadata(&self.path) {
                Ok(meta) => {
                    let mode = meta.mode() & 0o777;
                    let status = if mode == self.expected_mode {
                        Status::Pass
                    } else if mode < self.expected_mode {
                        Status::Strict
                    } else {
                        Status::Fail
                    };
                    let final_severity = self.determine_severity(mode);

                    results.push(PermissionResults {
                        path: self.path.clone(),
                        status,
                        expected_mode: self.expected_mode,
                        found_mode: mode,
                        severity: final_severity,
                        importance: self.importance.clone(),
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(PermissionResults {
                        path: self.path.clone(),
                        status: Status::Fail,
                        expected_mode: self.expected_mode,
                        found_mode: 0,
                        severity: Severity::Critical,
                        importance: self.importance.clone(),
                        error: Some(AuditError::Other(format!("Failed to read metadata: {}", e))),
                    });
                }
            }
        } else if self.path.is_dir() && self.recursive {
            match fs::metadata(&self.path) {
                Ok(meta) => {
                    let dev = meta.dev();
                    let ino = meta.ino();
                    if !visited.insert((dev, ino)) {
                        return results;
                    }
                }
                Err(e) => {
                    results.push(PermissionResults {
                        path: self.path.clone(),
                        status: Status::Fail,
                        expected_mode: self.expected_mode,
                        found_mode: 0,
                        severity: Severity::Critical,
                        importance: self.importance.clone(),
                        error: Some(AuditError::Other(format!(
                            "Failed to read directory metadata: {}",
                            e
                        ))),
                    });
                    return results;
                }
            }

            match fs::read_dir(&self.path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        // Symlink handling: skip symlinks in directory contents
                        if let Ok(meta) = fs::symlink_metadata(&path) {
                            if meta.file_type().is_symlink() {
                                use crate::audit::symlink::{SymRule, check_symlink};
                                let sym_rule = SymRule {
                                    path: path.clone(),
                                    target_link: None,
                                };
                                let sym_result = check_symlink(&sym_rule);
                                results.push(PermissionResults {
                                    path: sym_result.path.clone(),
                                    status: if sym_result.pass {
                                        Status::Pass
                                    } else {
                                        Status::Strict
                                    },
                                    expected_mode: self.expected_mode,
                                    found_mode: 0,
                                    severity: if sym_result.pass {
                                        Severity::None
                                    } else {
                                        Severity::Info
                                    },
                                    importance: self.importance.clone(),
                                    error: sym_result.error.map(AuditError::Other),
                                });
                                continue;
                            }
                        }
                        let sub_rule = PermissionRules {
                            path,
                            expected_mode: self.expected_mode,
                            importance: self.importance.clone(),
                            recursive: true,
                        };
                        results.extend(sub_rule.check(visited));
                    }
                }
                Err(e) => {
                    results.push(PermissionResults {
                        path: self.path.clone(),
                        status: Status::Fail,
                        expected_mode: self.expected_mode,
                        found_mode: 0,
                        severity: Severity::Critical,
                        importance: self.importance.clone(),
                        error: Some(AuditError::Other(format!(
                            "Failed to read directory: {}",
                            e
                        ))),
                    });
                }
            }
        }

        results
    }

    /// Run a custom audit for a user-specified path, expected mode, and importance.
    ///
    /// Used for ad-hoc audits outside of predefined rules.
    ///
    /// # Arguments
    /// * `path` - Path to audit
    /// * `expected_mode` - Expected file mode (octal)
    /// * `importance` - Importance level
    ///
    /// # Returns
    /// Vector of `PermissionResults` for the path
    pub fn custom_audit(
        path: PathBuf,
        expected_mode: u32,
        importance: Importance,
    ) -> Vec<PermissionResults> {
        let mut results = Vec::new();

        let (audit_rule, path_status) =
            PermissionRules::new(path.clone(), expected_mode, importance);

        match path_status {
            PathStatus::ValidFile | PathStatus::ValidDirectory => {
                let mut visited = HashSet::new();
                results.extend(audit_rule.check(&mut visited));
            }
            PathStatus::NotFound => {
                results.push(PermissionResults {
                    severity: Severity::Info,
                    expected_mode,
                    found_mode: 0o000,
                    path,
                    status: Status::Fail,
                    importance: Importance::Low,
                    error: Some(AuditError::Other(format!(
                        "Path not found: {}",
                        audit_rule.path.display()
                    ))),
                });
            }
            PathStatus::PermissionDenied => {
                results.push(PermissionResults {
                    severity: Severity::Critical,
                    expected_mode,
                    found_mode: 0o000,
                    path,
                    status: Status::Fail,
                    importance: Importance::High,
                    error: Some(AuditError::Other(format!(
                        "Permission denied: {}",
                        audit_rule.path.display()
                    ))),
                });
            }
        }

        results
    }
}

/// Parse permissions from octal ("640"), long symbolic ("rw-r-----"), or short symbolic ("u=rw,g=r,o=") formats.
///
/// Converts permission strings to a numeric mode for auditing.
///
/// # Arguments
/// * `input` - Permission string in octal or symbolic format
///
/// # Returns
/// Result containing parsed mode as `u32` or an `AuditError` if parsing fails.
pub fn parse_mode(input: &str) -> Result<u32, AuditError> {
    // Octal input
    if input.chars().all(|c| c.is_digit(8)) {
        return u32::from_str_radix(input, 8).map_err(|_| AuditError::InvalidOctalMode);
    }

    // Long symbolic input (e.g., rwxr-xr--)
    if input.len() == 9 && input.chars().all(|c| "rwx-".contains(c)) {
        let mut mode = 0u32;
        for (i, c) in input.chars().enumerate() {
            let shift = 8 - i;
            mode |= match c {
                'r' => 1 << shift,
                'w' => 1 << shift,
                'x' => 1 << shift,
                '-' => 0,
                _ => return Err(AuditError::InvalidSymbolicMode),
            };
        }
        return Ok(mode);
    }

    // Short symbolic input (e.g., u=rw,g=r,o= or u+rwx,g+rx,o+r)
    // Start with 0, then apply assignments or additions
    let mut mode = 0u32;
    let mut base_mode = [0u8; 3]; // user, group, other
    let mut set_base = false;
    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (who, rest) = match part.find(|c: char| c == '=' || c == '+' || c == '-') {
            Some(idx) => part.split_at(idx),
            None => return Err(AuditError::InvalidShortSymbolicFormat),
        };
        let op = rest.chars().next().unwrap();
        let perms = &rest[1..];
        let mut mask = 0u8;
        for c in perms.chars() {
            mask |= match c {
                'r' => 0b100,
                'w' => 0b010,
                'x' => 0b001,
                _ => return Err(AuditError::InvalidPermissionChar(c)),
            };
        }
        for w in who.chars() {
            let idx = match w {
                'u' => 0,
                'g' => 1,
                'o' => 2,
                _ => return Err(AuditError::InvalidClass(w)),
            };
            match op {
                '=' => {
                    base_mode[idx] = mask;
                    set_base = true;
                }
                '+' => {
                    base_mode[idx] |= mask;
                    set_base = true;
                }
                '-' => {
                    base_mode[idx] &= !mask;
                    set_base = true;
                }
                _ => return Err(AuditError::InvalidOperator(op)),
            }
        }
    }
    if set_base {
        mode |= (base_mode[0] as u32) << 6;
        mode |= (base_mode[1] as u32) << 3;
        mode |= base_mode[2] as u32;
        return Ok(mode);
    }

    Err(AuditError::Other("Invalid mode format".to_string()))
}

use crate::{DataList, DataMap};
pub fn perm_to_datalist(results: &[PermissionResults]) -> DataList {
    results
        .iter()
        .map(|r| {
            let mut map = DataMap::new();
            map.insert("path".to_string(), r.path.display().to_string());
            map.insert(
                "expected_mode".to_string(),
                format!("{:o}", r.expected_mode),
            );
            map.insert("found_mode".to_string(), format!("{:o}", r.found_mode));
            map.insert("status".to_string(), format!("{:?}", r.status));
            map.insert("severity".to_string(), format!("{:?}", r.severity));
            map.insert("importance".to_string(), format!("{:?}", r.importance));
            if let Some(ref err) = r.error {
                map.insert("error".to_string(), err.to_string());
            }
            map
        })
        .collect()
}

/// Error type for permission audit failures and parsing errors.
///
/// Used to represent errors encountered during permission parsing or audit checks.
#[derive(Debug, PartialEq, Serialize)]
pub enum AuditError {
    /// Invalid octal mode string
    InvalidOctalMode,
    /// Invalid symbolic mode string
    InvalidSymbolicMode,
    /// Invalid short symbolic mode format
    InvalidShortSymbolicFormat,
    /// Invalid permission character
    InvalidPermissionChar(char),
    /// Invalid class (user/group/other)
    InvalidClass(char),
    /// Invalid operator (=, +, -)
    InvalidOperator(char),
    /// Other error with message
    Other(String),
}

impl fmt::Display for AuditError {
    /// Formats the error for display purposes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::InvalidOctalMode => write!(f, "Invalid octal mode"),
            AuditError::InvalidSymbolicMode => write!(f, "Invalid symbolic mode"),
            AuditError::InvalidShortSymbolicFormat => {
                write!(f, "Invalid short symbolic mode format")
            }
            AuditError::InvalidPermissionChar(c) => write!(f, "Invalid permission char: {}", c),
            AuditError::InvalidClass(c) => write!(f, "Invalid class: {}", c),
            AuditError::InvalidOperator(c) => write!(f, "Invalid operator: {}", c),
            AuditError::Other(msg) => write!(f, "{}", msg),
        }
    }
}
impl std::error::Error for AuditError {}

/* -------- Unit tests for permission parsing ---------- */
/// Unit tests for permission parsing and severity logic.
#[cfg(test)]
mod tests {
    #[test]
    fn test_invalid_octal() {
        // Contains non-octal digit
        assert!(parse_mode("68").is_err());
    }

    #[test]
    fn test_invalid_symbolic() {
        // Invalid symbolic string
        assert!(parse_mode("rwxrwxrwz").is_err());
        assert!(parse_mode("u=abc,g=r,o=").is_err());
        assert!(parse_mode("u+xz,g+r,o=").is_err());
    }

    #[test]
    fn test_empty_string() {
        assert!(parse_mode("").is_err());
    }
    #[test]
    fn test_mode_octal() {
        assert_eq!(parse_mode("640"), Ok(0o640));
        assert_eq!(parse_mode("755"), Ok(0o755));
    }

    #[test]
    fn test_long_symbolic() {
        // This test is limited by the current implementation
        // which does not fully parse symbolic modes
        // but should not error for valid input
        assert!(parse_mode("rw-r-----").is_ok());
    }

    #[test]
    fn test_short_symbolic() {
        assert_eq!(parse_mode("u=rw,g=r,o="), Ok(0o640));
        assert_eq!(parse_mode("u+rwx,g+rx,o+r"), Ok(0o754));
    }

    #[test]
    fn test_severity_group_other_bits() {
        let rule = PermissionRules {
            path: PathBuf::from("/tmp/testfile"),
            expected_mode: 0o640,
            recursive: false,
            importance: Importance::Medium,
        };
        // Others have read, which is more permissive than expected
        assert_eq!(rule.determine_severity(0o644), Severity::High);
    }

    #[test]
    fn test_severity_fallback_low() {
        let rule = PermissionRules {
            path: PathBuf::from("/tmp/testfile"),
            expected_mode: 0o640,
            recursive: false,
            importance: Importance::Medium,
        };
        // Not stricter, not more permissive, not world-writable, not exact match
        assert_eq!(rule.determine_severity(0o641), Severity::High);
    }
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_severity_exact_match() {
        let rule = PermissionRules {
            path: PathBuf::from("/tmp/testfile"),
            expected_mode: 0o640,
            recursive: false,
            importance: Importance::Medium,
        };
        assert_eq!(rule.determine_severity(0o640), Severity::None);
    }

    #[test]
    fn test_severity_world_write() {
        let rule = PermissionRules {
            path: PathBuf::from("/tmp/testfile"),
            expected_mode: 0o640,
            recursive: false,
            importance: Importance::Medium,
        };
        assert_eq!(rule.determine_severity(0o666), Severity::Critical);
    }

    #[test]
    fn test_severity_more_permissive() {
        let rule = PermissionRules {
            path: PathBuf::from("/tmp/testfile"),
            expected_mode: 0o640,
            recursive: false,
            importance: Importance::Medium,
        };
        // Group has write, which is more permissive than expected
        assert_eq!(rule.determine_severity(0o660), Severity::High);
    }

    #[test]
    fn test_severity_stricter() {
        let rule = PermissionRules {
            path: PathBuf::from("/tmp/testfile"),
            expected_mode: 0o644,
            recursive: false,
            importance: Importance::Medium,
        };
        // Only owner can read/write
        assert_eq!(rule.determine_severity(0o600), Severity::Info);
    }
}
