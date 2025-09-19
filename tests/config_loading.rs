// Integration test for TOML config loading in HALO
use alhalo::toml_permissions;
use std::io::Write;

#[test]
fn test_valid_toml_config_loading() {
    // Create the file to be referenced in the TOML config
    let mut target_file = tempfile::NamedTempFile::new().expect("Failed to create target file");
    // Optionally write something to the file
    writeln!(target_file, "test").ok();
    let target_path = target_file.path().to_str().unwrap();

    // Build TOML config referencing the temp file
    let toml_content = format!(
        "[[rules]]\npath = \"{}\"\nexpected_mode = 644\nimportance = \"Medium\"\nrecursive = false\n",
        target_path
    );
    let mut toml_file = tempfile::NamedTempFile::new().expect("Failed to create TOML file");
    write!(toml_file, "{}", toml_content).expect("Failed to write TOML");
    let toml_path = toml_file.path().to_str().unwrap();
    let config = toml_permissions(toml_path).expect("Should load TOML config");
    assert!(!config.is_empty());
    assert_eq!(config[0].expected_mode, 0o644);
}
