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
//! use alhalo::OwnershipRule;
//! let rule = OwnershipRule {
//!     path: "/etc/shadow".into(),
//!     expected_uid: 0,
//!     expected_gid: 42,
//!     follow_symlinks: false,
//!     recursive: false,
//! };
//! let result = rule.check_ownership();
//! println!("UID: {:?}, GID: {:?}, Pass: {}", result.found_uid, result.found_gid, result.pass);
//! ```

use crate::{PathStatus, Severity, SymRule, check_symlink};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use crate::render_output::{Renderable, DataList as RenderDataList, DataMap};
use indexmap::IndexMap;

/// Result of an ownership audit.
///
/// Contains the actual and expected UID/GID, pass/fail status, and error info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OwnershipResult {
    pub path: PathBuf,
    pub expected_uid: Option<u32>,
    pub expected_gid: Option<u32>,
    pub found_uid: Option<u32>,
    pub found_gid: Option<u32>,
    pub pass: bool,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Renderable for OwnershipResult {
    fn to_datalist(&self) -> RenderDataList {
        let mut map = IndexMap::new();
        map.insert("path".to_string(), self.path.display().to_string());
        map.insert("expected_uid".to_string(), 
            self.expected_uid.map_or("N/A".to_string(), |uid| uid.to_string()));
        map.insert("expected_gid".to_string(), 
            self.expected_gid.map_or("N/A".to_string(), |gid| gid.to_string()));
        map.insert("found_uid".to_string(), 
            self.found_uid.map_or("N/A".to_string(), |uid| uid.to_string()));
        map.insert("found_gid".to_string(), 
            self.found_gid.map_or("N/A".to_string(), |gid| gid.to_string()));
        map.insert("pass".to_string(), self.pass.to_string());
        map.insert("severity".to_string(), format!("{:?}", self.severity));
        if let Some(ref err) = self.error {
            map.insert("error".to_string(), err.clone());
        }
        vec![map]
    }
    
    fn pretty_print(&self) -> String {
        let status_symbol = if self.pass { "✓" } else { "✗" };
        
        let mut result = format!(
            "{} {} (UID: {}/{}, GID: {}/{}) - {:?}",
            status_symbol,
            self.path.display(),
            self.found_uid.map_or("?".to_string(), |uid| uid.to_string()),
            self.expected_uid.map_or("?".to_string(), |uid| uid.to_string()),
            self.found_gid.map_or("?".to_string(), |gid| gid.to_string()),
            self.expected_gid.map_or("?".to_string(), |gid| gid.to_string()),
            self.severity
        );
        
        if let Some(ref err) = self.error {
            result.push_str(&format!(" [Error: {}]", err));
        }
        
        result
    }
}

/// Represents an ownership audit rule for a file or directory.
///
/// Used to specify the expected UID and GID for a given path.
#[derive(Debug, Clone)]
pub struct OwnershipRule {
    pub path: PathBuf,
    pub expected_uid: u32,
    pub expected_gid: u32,
    /// If true, follow symlinks
    pub follow_symlinks: bool,
    pub recursive: bool,
}

impl OwnershipRule {
    pub fn new(
        path: PathBuf,
        expected_uid: u32,
        expected_gid: u32,
        follow_symlinks: bool,
    ) -> (Self, PathStatus) {
        if !path.exists() {
            return (
                OwnershipRule {
                    path,
                    expected_uid,
                    expected_gid,
                    follow_symlinks,
                    recursive: false,
                },
                PathStatus::NotFound,
            );
        }

        match fs::metadata(&path) {
            Ok(meta) => {
                if meta.is_file() {
                    (
                        OwnershipRule {
                            path,
                            expected_uid,
                            expected_gid,
                            follow_symlinks,
                            recursive: false,
                        },
                        PathStatus::ValidFile,
                    )
                } else if meta.is_dir() {
                    (
                        OwnershipRule {
                            path,
                            expected_uid,
                            expected_gid,
                            follow_symlinks,
                            recursive: true,
                        },
                        PathStatus::ValidDirectory,
                    )
                } else {
                    (
                        OwnershipRule {
                            path,
                            expected_uid,
                            expected_gid,
                            follow_symlinks,
                            recursive: false,
                        },
                        PathStatus::NotFound,
                    )
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    (
                        OwnershipRule {
                            path,
                            expected_uid,
                            expected_gid,
                            follow_symlinks,
                            recursive: false,
                        },
                        PathStatus::PermissionDenied,
                    )
                } else {
                    (
                        OwnershipRule {
                            path,
                            expected_uid,
                            expected_gid,
                            follow_symlinks,
                            recursive: false,
                        },
                        PathStatus::NotFound,
                    )
                }
            }
        }
    }

    /// Determine ownership audit severity
    pub fn owner_severity(&self, uid: u32, gid: u32) -> Severity {
        // If audit passes, no severity
        if uid == self.expected_uid && gid == self.expected_gid {
            return Severity::None;
        }

        // Root mismatch is always critical
        if self.expected_uid == 0 || self.expected_gid == 0 {
            return Severity::Critical;
        }

        // If expected UID/GID is a system account (e.g., <100), treat as High
        if self.expected_uid < 100 || self.expected_gid < 100 {
            return Severity::High;
        }

        // If expected UID/GID is user's own account (e.g., >999), treat as Info
        if self.expected_uid >= 1000 || self.expected_gid >= 1000 {
            return Severity::Info;
        }

        // Otherwise, treat as Low severity
        Severity::Low
    }

    /// Checks ownership of the given path against expected UID and GID.
    /// Uses symlink audit module for symlink paths.
    pub fn check_ownership(&self) -> OwnershipResult {
        // Symlink handling: delegate to symlink audit module
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.file_type().is_symlink() {
                let sym_rule = SymRule {
                    path: self.path.clone(),
                    target_link: None, // Optionally pass expected target
                };
                let sym_result = check_symlink(&sym_rule);
                return OwnershipResult {
                    path: sym_result.path.clone(),
                    expected_uid: Some(self.expected_uid),
                    expected_gid: Some(self.expected_gid),
                    found_uid: None,
                    found_gid: None,
                    pass: sym_result.pass,
                    severity: if sym_result.pass {
                        Severity::None
                    } else {
                        Severity::Critical
                    },
                    error: sym_result.error,
                };
            }
        }
        // Non-symlink: regular ownership check
        let meta_result = if self.follow_symlinks {
            fs::metadata(&self.path)
        } else {
            fs::symlink_metadata(&self.path)
        };
        match meta_result {
            Ok(meta) => {
                let found_uid = meta.uid();
                let found_gid = meta.gid();
                let pass = found_uid == self.expected_uid && found_gid == self.expected_gid;
                OwnershipResult {
                    path: self.path.clone(),
                    expected_uid: Some(self.expected_uid),
                    expected_gid: Some(self.expected_gid),
                    found_uid: Some(found_uid),
                    found_gid: Some(found_gid),
                    pass,
                    severity: self.owner_severity(found_uid, found_gid),
                    error: None,
                }
            }
            Err(e) => OwnershipResult {
                path: self.path.clone(),
                expected_uid: Some(self.expected_uid),
                expected_gid: Some(self.expected_gid),
                found_uid: None,
                found_gid: None,
                pass: false,
                severity: Severity::Critical,
                error: Some(format!("Failed to read metadata: {}", e)),
            },
        }
    }
}

/// Converts a vector of OwnershipResult to DataList for CSV/text rendering
pub fn ownership_to_datalist(results: &[OwnershipResult]) -> RenderDataList {
    results
        .iter()
        .map(|r| {
            let mut map = DataMap::new();
            map.insert("path".to_string(), r.path.display().to_string());
            map.insert(
                "expected_uid".to_string(),
                r.expected_uid.map(|u| u.to_string()).unwrap_or_default(),
            );
            map.insert(
                "expected_gid".to_string(),
                r.expected_gid.map(|g| g.to_string()).unwrap_or_default(),
            );
            map.insert(
                "found_uid".to_string(),
                r.found_uid.map(|u| u.to_string()).unwrap_or_default(),
            );
            map.insert(
                "found_gid".to_string(),
                r.found_gid.map(|g| g.to_string()).unwrap_or_default(),
            );
            map.insert("pass".to_string(), r.pass.to_string());
            map.insert("severity".to_string(), format!("{:?}", r.severity));
            if let Some(ref err) = r.error {
                map.insert("error".to_string(), err.clone());
            }
            map
        })
        .collect()
}
