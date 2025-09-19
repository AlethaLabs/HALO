//! Permission Fix Script Generator for HALO
//!
//! This module generates shell scripts to fix file and directory permissions based on audit results.
//!
//! Usage:
//! - Call `generate_fix_script` with a slice of `PermissionResults`.
//! - Returns a shell script as a String with recommended `chmod` commands.

use alhalo::PermissionResults;

/// Generates a shell script to fix permissions for failed audit results.
///
/// # Arguments
/// * `results` - Slice of `PermissionResults` from an audit
///
/// # Returns
/// A shell script as a String with recommended `chmod` commands for each failed result.
pub fn generate_fix_script(results: &[PermissionResults]) -> String {
    let mut script = String::from("#!/bin/bash\n# HALO Permission Fix Script\n\n");
    for res in results {
        if res.status == alhalo::Status::Fail {
            script.push_str(&format!(
                "chmod {:o} {}\n",
                res.expected_mode,
                res.path.display()
            ));
        }
    }
    script
}

// Future: Add support for ownership fixes, symlink handling, and dry-run mode.
