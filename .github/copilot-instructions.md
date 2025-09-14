# Copilot Instructions for Aletha Labs HALO

This document guides AI coding agents to be productive in the HALO codebase. HALO is a Rust CLI tool for auditing and rendering Linux system configuration and permissions, designed for both home users and sysadmins.

## Architecture Overview
- **Entry Point:** `src/main.rs` launches a REPL-like CLI loop via `cli()`.
- **CLI Logic:** `src/cli.rs` defines commands (`parse`, `check`) using `clap`. Input is parsed and dispatched to handlers.
- **Handlers:**
  - `handle_file` (in `src/handle_args.rs`) parses files into structured data.
  - `handle_check` (in `src/handle_args.rs`) runs permission audits using rules from `src/audit/`.
- **Audit System:**
  - `src/audit/audit_permissions.rs` defines audit rules, severity, and result structures. Supports recursive directory audits and custom rules.
  - `src/audit/default_permissions.rs` provides built-in rules for user, system, network, and log files.
- **Rendering:** Output formats (pretty, json, csv) are handled in `src/render_output.rs` and via the `render!` macro.

## Developer Workflows
- **Build:** Use `cargo build` or `cargo run` to compile and launch the CLI.
- **Test:** No standard Rust test files detected; audits are run interactively via CLI commands (see below).
- **Debug:** Use CLI commands interactively. Example: `parse --file /etc/passwd --format json` or `check --target user`.

## Project-Specific Patterns
- **Audit Rule Expansion:** Add new audit targets by extending `AuditTarget` enum and implementing corresponding config structs in `src/audit/default_permissions.rs`.
- **Permission Checks:** All permission logic is centralized in `AuditRule` and `AuditPermissions` trait. Custom audits use `AuditRule::custom_audit()`.
- **Data Parsing:** File parsing expects colon-separated key-value pairs. See `handle_file()` for details.
- **Output Rendering:** Use the `render!` macro for consistent output formatting.
- **Error Handling:** Errors are surfaced to CLI output; critical errors are marked in audit results.

## Integration Points
- **External Dependencies:** Uses `clap` for CLI, `serde`/`serde_json` for serialization, `indexmap` for deterministic maps, and `toml` for config parsing.
- **Extensibility:** To add new audit rules, update config structs and implement the `AuditPermissions` trait.
- **Config Files:** TOML config support is present but not fully documented; see `check --toml <file>` usage.

## Examples
- Audit user files: `check --target user`
- Custom audit: `check --path /etc/shadow --expect 640 --importance high`
- Parse and render file: `parse --file /proc/cpuinfo --format json`

## Key Files & Directories
- `src/main.rs` — CLI entry point
- `src/cli.rs` — Command parsing and dispatch
- `src/handle_args.rs` — File parsing and audit handling
- `src/audit/` — Audit logic and default rules
- `src/render_output.rs` — Output formatting

---
**Feedback:** If any section is unclear or missing, please specify what needs improvement or additional detail.
