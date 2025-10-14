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
- Updated [documentaion](https://docs.rs/alhalo/0.1.12/alhalo/index.html)

## [0.1.4] - 2025-9-16
- Seperated CLI binary from Library API
- Updated documentation/readme

## [0.2.0] - 2025-9-19
- **Starting this day (Friday - 2025-9-19) there will be minor-major releases once per month**
- Changed AuditRule -> PermissionRules for clarity of use
- Added symbolic link detection/auditing functionality
- Updated documentation in [lib](lib.rs), and [README](README.md)
- Updated docs
- Added more (examples)[examples]
- Fixed seperation concerns of library and binary files
- Added better output configuration for Audits
- Advanced Ownership checks and configurations
- Added toml support for Ownership/Symlink configuration
- Improved error handling/reporting
- Added beginnings of [fix_script](audit/fix_script.rs) which can automaticaly fix mismatched permssions

## [0.3.0] - 2025-10-14
- Fixed several bugs with CLI
- **Deprecated render! macro**
    - Added new **Renderable** trait for code hygiene
- Added start of network monitoring
    - Discover devices on local network
- Updated examples/tests
- Updated documentation