//! Prelude module for easy imports
//! 
//! This module re-exports the most commonly used types and traits from the library.
//! Users can import everything they need with a single line:
//! 
//! ```rust
//! use alhalo::prelude::*;
//! ```

// Core audit types
pub use crate::audit::permissions::audit_permissions::{
    AuditPermissions, PermissionResults, PermissionRules, 
    Importance, PathStatus, Status, Severity
};

// Configuration types
pub use crate::audit::permissions::default_permissions::{
    UserConfig, SysConfig, NetConf, Log
};

// Ownership types
pub use crate::audit::ownership::ownership::{
    OwnershipResult, OwnershipRule
};

// Symlink types
pub use crate::audit::symlink::{SymResult, SymRule, check_symlink};

// Rendering traits and types
pub use crate::render_output::{
    Renderable, OutputFormat, DataList, DataMap
};

// TOML configuration
pub use crate::audit::toml_config::{
    AuditConfig, PermissionConfig, OwnerConfig
};