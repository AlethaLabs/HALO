// Integration test: run a user audit and check output
use alhalo::{AuditPermissions, UserConfig, render_json};

#[test]
fn user_audit_json_output() {
    let results = UserConfig::default().run_audit_perms();
    let json = render_json(&results).expect("Should render JSON");
    assert!(json.contains("/etc/passwd"));
    assert!(json.contains("expected_mode"));
    assert!(json.contains("found_mode"));
}
