//!
//! Default audit rule definitions for common Linux system files and directories.
//!
//! This module provides built-in audit rules for user, system, network, and log files.
//! These rules are used by the audit engine to check file and directory permissions against best practices.
//!
//! To extend or customize, add new config structs and implement the `AuditPermissions` trait.
//!

use crate::impl_audit;
use crate::{AuditPermissions, Importance, PermissionRules};
use std::path::PathBuf;

/// Audit rules for user and authentication files.
///
/// Includes `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, and `/etc/pam.d`.
///
/// Used to check permissions for files critical to user management and authentication.
pub struct UserConfig {
    passwd: PathBuf,
    shadow: PathBuf,
    group: PathBuf,
    gshadow: PathBuf,
    sudoers: PathBuf,
    pamd: PathBuf,
}

/// Provides default paths for user and authentication files.
impl Default for UserConfig {
    fn default() -> Self {
        Self {
            passwd: "/etc/passwd".into(),
            shadow: "/etc/shadow".into(),
            group: "/etc/group".into(),
            gshadow: "/etc/gshadow".into(),
            sudoers: "/etc/sudoers".into(),
            pamd: "/etc/pam.d".into(),
        }
    }
}

// Implements audit rules for UserConfig using the impl_audit macro.
impl_audit! {
    UserConfig,
    self,
    [
        {path: &self.passwd, expected_mode: 0o644, importance: Importance::Medium, recursive: false},
        {path: &self.shadow, expected_mode: 0o600, importance: Importance::High, recursive: false},
        {path: &self.group, expected_mode: 0o644, importance: Importance::Medium, recursive: false},
        {path: &self.gshadow, expected_mode: 0o600, importance: Importance::High, recursive: false},
        {path: &self.sudoers, expected_mode: 0o440, importance: Importance::High, recursive: false},
        // The directory itself should be 755, note recursive is false here
        {path: &self.pamd, expected_mode: 0o755, importance: Importance::High, recursive: false},
        // Files within pam.d should be 644
        {path: &self.pamd, expected_mode: 0o644, importance: Importance::High, recursive: true}
    ]
}

/// Audit rules for system configuration and boot files.
///
/// Includes `/boot/grub/grub.cfg`, `/etc/fstab`, `/etc/sysctl.conf`, and `/etc/systemd`.
pub struct SysConfig {
    grubcfg: PathBuf,
    fstab: PathBuf,
    sysctl: PathBuf,
    systemd: PathBuf,
}

/// Provides default paths for system configuration and boot files.
impl Default for SysConfig {
    fn default() -> Self {
        Self {
            grubcfg: "/boot/grub/grub.cfg".into(),
            fstab: "/etc/fstab".into(),
            sysctl: "/etc/sysctl.conf".into(),
            systemd: "/etc/systemd".into(),
        }
    }
}

// Implements audit rules for SysConfig
impl_audit! {
    SysConfig,
    self,
    [
        {path: &self.grubcfg, expected_mode: 0o640, importance: Importance::High, recursive: false},
        {path: &self.fstab, expected_mode: 0o644, importance: Importance::Medium, recursive: false},
        {path: &self.sysctl, expected_mode: 0o644, importance: Importance::Medium, recursive: false},
        {path: &self.systemd, expected_mode: 0o644, importance: Importance::High, recursive: true}
    ]
}

/// Audit rules for network configuration files.
///
/// Includes `/etc/hosts`, `/etc/resolv.conf`, and `/etc/network/interfaces`.
pub struct NetConf {
    hosts: PathBuf,
    resolv_cfg: PathBuf,
    interface: PathBuf,
}

/// Provides default paths for network configuration files.
impl Default for NetConf {
    fn default() -> Self {
        Self {
            hosts: "/etc/hosts".into(),
            resolv_cfg: "/etc/resolv.conf".into(),
            interface: "/etc/network/interfaces".into(),
        }
    }
}

// Implements audit rules for NetConf
impl_audit! {
    NetConf,
    self,
    [
        {path: &self.hosts, expected_mode: 0o644, importance: Importance::Low, recursive: false},
        {path: &self.resolv_cfg, expected_mode: 0o644, importance: Importance::Low, recursive: false},
        {path: &self.interface, expected_mode: 0o644, importance: Importance::Medium, recursive: false}
    ]
}

/// Audit rules for log files.
///
/// Includes `/var/log/wtmp` and `/var/log/btmp`.
pub struct Log {
    wtmp: PathBuf,
    btmp: PathBuf,
}

/// Provides default paths for log files.
impl Default for Log {
    fn default() -> Self {
        Self {
            wtmp: "/var/log/wtmp".into(),
            btmp: "/var/log/btmp".into(),
        }
    }
}

// Implements audit rules for Log
impl_audit! {
    Log,
    self,
    [
        {path: &self.wtmp, expected_mode: 0o664, importance: Importance::High, recursive: false},
        {path: &self.btmp, expected_mode: 0o664, importance: Importance::High, recursive: false}
    ]
}
