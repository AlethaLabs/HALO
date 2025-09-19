// Integration tests for edge cases in HALO
use alhalo::{AuditError, AuditPermissions, Log, parse_mode, render_json};

#[test]
fn test_nonexistent_file_audit() {
    let results = alhalo::PermissionRules::custom_audit(
        std::path::PathBuf::from("/tmp/this_file_should_not_exist"),
        0o644,
        alhalo::Importance::Low,
    );
    assert!(!results.is_empty());
    assert!(results[0].status == alhalo::Status::Fail);
    assert!(results[0].error.is_some());
}

#[test]
fn test_invalid_permission_parse() {
    let result = parse_mode("not_a_mode");
    assert!(matches!(result, Err(AuditError::Other(_)) | Err(_)));
}

#[test]
fn test_empty_config_audit() {
    // Simulate an empty config struct
    struct EmptyConfig;
    impl AuditPermissions for EmptyConfig {
        fn rules(&self) -> Vec<alhalo::PermissionRules> {
            vec![]
        }
    }
    let results = EmptyConfig.run_audit_perms();
    assert!(results.is_empty());
}

#[test]
fn test_log_audit_output() {
    let results = Log::default().run_audit_perms();
    let json = render_json(&results).unwrap();
    assert!(json.contains("/var/log/wtmp"));
    assert!(json.contains("/var/log/btmp"));
}
