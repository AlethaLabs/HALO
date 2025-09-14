//! Ownership audit logic for HALO
//!
//! This module provides types and functions for auditing file and directory ownership.
//!
//! # Features
//! - Define ownership rules for files and directories
//! - Check actual UID/GID against expected values
//! - Return detailed results including errors
//!
//! # Example Usage
//! ```rust
//! use halo::audit::ownership::{OwnershipRule, check_ownership};
//! let rule = OwnershipRule {
//!     path: "/etc/shadow".into(),
//!     expected_uid: 0,
//!     expected_gid: 42,
//! };
//! let result = check_ownership(&rule);
//! println!("UID: {:?}, GID: {:?}, Pass: {}", result.found_uid, result.found_gid, result.pass);
//! ```
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// Represents an ownership audit rule for a file or directory.
///
/// Used to specify the expected UID and GID for a given path.
#[derive(Debug, Clone)]
pub struct OwnershipRule {
    pub path: PathBuf,
    pub expected_uid: u32,
    pub expected_gid: u32,
}

/// Result of an ownership audit.
///
/// Contains the actual and expected UID/GID, pass/fail status, and error info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnershipResult {
    pub path: PathBuf,
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub found_uid: Option<u32>,
    pub found_gid: Option<u32>,
    pub pass: bool,
    pub error: Option<String>,
}

/// Checks ownership of the given path against expected UID and GID.
///
/// Returns an `OwnershipResult` with found UID/GID, pass/fail, and error details.
///
/// # Arguments
/// * `rule` - OwnershipRule specifying path and expected UID/GID
///
/// # Returns
/// * `OwnershipResult` - Result of the audit
pub fn check_ownership(rule: &OwnershipRule) -> OwnershipResult {
    match fs::metadata(&rule.path) {
        Ok(meta) => {
            let found_uid = meta.uid();
            let found_gid = meta.gid();
            let pass = found_uid == rule.expected_uid && found_gid == rule.expected_gid;
            OwnershipResult {
                path: rule.path.clone(),
                expected_uid: rule.expected_uid,
                expected_gid: rule.expected_gid,
                found_uid: Some(found_uid),
                found_gid: Some(found_gid),
                pass,
                error: None,
            }
        }
        Err(e) => OwnershipResult {
            path: rule.path.clone(),
            expected_uid: rule.expected_uid,
            expected_gid: rule.expected_gid,
            found_uid: None,
            found_gid: None,
            pass: false,
            error: Some(format!("Failed to read metadata: {}", e)),
        },
    }
}
