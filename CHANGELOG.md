# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Modularized CLI command handlers for maintainability
- Ownership audit logic and UID/GID checks integrated
- Permission audit logic refactored for extensibility
- Bash completion handler 
- Improved documentation for CLI and audit modules
- Error handling and user feedback improved
- Core audit logic for user, system, network, and log files
- CLI and library APIs
- TOML config support
- Output rendering in JSON, CSV, and pretty formats

## [0.1.0] - 2025-09-13
- First public release

## [0.1.1] - 2025-9-14
- Fixed bugs, updated doc comments

## [0.1.3] - 2025-9-15
- Added PermissionDenied to PathStatus enum 
- Added symlink handling
- Updated (documentaion)[https://docs.rs/alhalo/0.1.12/alhalo/index.html]