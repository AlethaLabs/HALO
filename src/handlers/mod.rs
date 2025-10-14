//! Handler modules for HALO CLI commands
//!
//! This module contains individual handlers for each CLI command:
//! - `parse`: File parsing and rendering
//! - `check`: Permission and ownership auditing
//! - `net`: Network discovery
//! - `bash`: Shell completion generation
//! - `file`: File reading and parsing utilities

pub mod parse;
pub mod check;
pub mod net;
pub mod bash;
pub mod file;

// Re-export handler functions used by CLI
pub use parse::handle_parse;
pub use check::handle_check;
pub use net::handle_net;
pub use bash::handle_bash;