// Note: the rener_json import is necessary for the macro render! to work correctly
use alhalo::{Importance, PathStatus, PermissionResults, PermissionRules, render, render_json};
use std::collections::HashSet;

// Create an audit rule for /etc/passwd with expected mode 644 and medium importance
fn main() {
    let (rule, status) = PermissionRules::new("/etc/passwd".into(), 0o644, Importance::Medium);

    // Run the audit (checks permissions and returns results)
    let mut visited = HashSet::new();
    let results: Vec<PermissionResults> = rule.check(&mut visited);

    // Handle the case where the path does not exist
    match status {
        PathStatus::NotFound => {
            eprintln!("Warning: Path {} not found", rule.path.display());
            return;
        }
        _ => {
            // Print the results using alhalo render! macro
            match render!(&results, Some("json")) {
                Ok(output) => println!("{}", output),
                Err(e) => eprintln!("Error rendering results: {}", e),
            }
        }
    }
}
