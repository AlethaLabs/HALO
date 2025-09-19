use alhalo::{AuditPermissions, Importance, PermissionRules, UserConfig};

fn main() {
    // Audit /etc/passwd with expected mode 0o644 and medium importance
    let (rule, _status) = PermissionRules::new("/etc/passwd".into(), 0o644, Importance::Medium);

    let results = rule.check(&mut std::collections::HashSet::new());
    for result in results {
        println!("Single file audit: {:?}", result);
    }

    // Or audit all default user files:
    let user_config = UserConfig::default();
    let all_results = user_config.run_audit_perms();
    for result in all_results {
        println!("UserConfig audit: {:?}", result);
    }
}
