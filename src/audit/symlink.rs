//! Symlink audit logic for HALO
//!
//! This module provides types and functions for auditing symbolic links in the filesystem.
//!
//! # Features
//! - Check if a path is a symlink
//! - Compare symlink target to an expected value
//! - Report broken symlinks and errors
//! - Return detailed results for use in CLI and library
//!
//! # Example Usage
//! ```rust
//! use alhalo::SymRule;
//! use alhalo::check_symlink;
//! let rule = SymRule {
//!     path: "/etc/ssl/certs/ca-certificates.crt".into(),
//!     target_link: Some("/usr/lib/ssl/certs/ca-certificates.crt".into()),
//! };
//! let result = check_symlink(&rule);
//! println!("Target: {:?}, Pass: {}", result.target, result.pass);
//! ```
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Represents a symlink audit rule for a file or directory.
///
/// Used to specify the path of the symlink and the expected target (if any).
/// If `target_link` is `None`, only existence and type are checked.
#[derive(Debug, Clone)]
pub struct SymRule {
    pub path: PathBuf,
    pub target_link: Option<PathBuf>,
}

/// Result of a symlink audit.
///
/// Contains the actual and expected target, pass/fail status, and error info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymResult {
    pub path: PathBuf,
    pub target: Option<PathBuf>,
    pub target_link: Option<PathBuf>,
    pub pass: bool,
    pub error: Option<String>,
}

/// Checks a symlink for existence and target match.
///
/// Returns a `SymResult` with the actual target, expected target, pass/fail, and error details.
///
/// # Arguments
/// * `rule` - SymRule specifying path and expected target
///
/// # Returns
/// * `SymResult` - Result of the symlink audit
pub fn check_symlink(rule: &SymRule) -> SymResult {
    if !rule.path.exists() {
        return SymResult {
            path: rule.path.clone(),
            target: None,
            target_link: rule.target_link.clone(),
            pass: false,
            error: Some("Symlink not found".to_string()),
        };
    }
    match fs::symlink_metadata(&rule.path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                match fs::read_link(&rule.path) {
                    Ok(target) => {
                        let pass = match &rule.target_link {
                            Some(expected) => &target == expected,
                            None => true,
                        };
                        SymResult {
                            path: rule.path.clone(),
                            target: Some(target),
                            target_link: rule.target_link.clone(),
                            pass,
                            error: None,
                        }
                    }
                    Err(e) => SymResult {
                        path: rule.path.clone(),
                        target: None,
                        target_link: rule.target_link.clone(),
                        pass: false,
                        error: Some(format!("Failed to read symlink target: {}", e)),
                    },
                }
            } else {
                SymResult {
                    path: rule.path.clone(),
                    target: None,
                    target_link: rule.target_link.clone(),
                    pass: false,
                    error: Some("Path is not a symlink".to_string()),
                }
            }
        }
        Err(e) => SymResult {
            path: rule.path.clone(),
            target: None,
            target_link: rule.target_link.clone(),
            pass: false,
            error: Some(format!("Failed to get metadata: {}", e)),
        },
    }
}
