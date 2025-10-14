//! Macros for audit trait implementation in HALO.
//!
//! This module provides:
//! - `impl_audit!`: Macro to implement the `AuditPermissions` trait for config structs
//!
//! Note: The `render!` macro has been deprecated in favor of the trait-based rendering system.
//! Use the `Renderable` trait and `.render_and_print()` method instead.
/// DEPRECATED: Macro for rendering output in various formats for CLI commands.
///
/// This macro is deprecated in favor of the trait-based rendering system.
/// Use the `Renderable` trait and `.render_and_print()` method instead.
///
/// # Usage
/// - For the `Parse` command: `render!(data, format, line)`
///   - Supports filtering by line/key and output formats: json, csv, pretty text.
/// - For the `Check` command: `render!(data, format)`
///   - Only supports JSON output.
///
/// Returns a `Result<String, std::io::Error>` with the rendered output or error.
#[deprecated(
    since = "0.1.0",
    note = "Use the Renderable trait and render_and_print() method instead"
)]
#[macro_export]
macro_rules! render {
    // Case 1: For the Parse command, which has a line filter
    ($data:expr, $format:expr, $line:expr) => {{
        let filter_data = match $line {
            Some(ref l) => filter($data, l),
            None => filter($data, &[]),
        };

        match $format.as_deref() {
            Some("json") => render_json(&filter_data),
            Some("csv") => match $line.as_deref() {
                Some(l) => render_csv(&filter_data, l),
                None => render_csv(&filter_data, &[]),
            },
            _ => match $line.as_deref() {
                Some(l) => render_text(&filter_data, l),
                None => render_text(&filter_data, &[]),
            },
        }
    }};

    // Case 2: For the Check command, which has no line filter
    ($data:expr, $format:expr) => {{
        match $format.as_deref() {
            Some("json") => render_json($data),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unsupported format for this command",
            )),
        }
    }};
}

/// Macro to implement the `AuditPermissions` trait for config structs.
///
/// Reduces boilerplate for defining audit rules for system files and directories.
///
/// # Example
/// ```ignore
/// impl_audit! {
///     MyConfig,
///     self,
///     [
///         {path: &self.file, expected_mode: 0o644, importance: Importance::Medium, recursive: false},
///         // ...
///     ]
/// }
/// ```
#[macro_export]
macro_rules! impl_audit {
    ($struct_name:ident, $s:ident, [
        $( { path: $path:expr, expected_mode: $expected_mode:expr, importance: $importance:expr, recursive: $recursive:expr } ),*
    ]) => {
        impl AuditPermissions for $struct_name {
            fn rules(&$s) -> Vec<PermissionRules> {
                vec![
                    $(
                        PermissionRules {
                            path: $path.clone(),
                            expected_mode: $expected_mode,
                            importance: $importance,
                            recursive: $recursive,
                        },
                    )*
                ]
            }
        }
    };
}
