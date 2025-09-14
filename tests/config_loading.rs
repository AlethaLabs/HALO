// Integration test for TOML config loading in HALO
use halo::load_toml_rules;
use std::io::Write;

#[test]
fn test_valid_toml_config_loading() {
    let toml_content = r#"
[[rules]]
path = "/tmp/testfile"
expected_mode = 644
importance = "Medium"
recursive = false
    "#;
    let mut file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    write!(file, "{}", toml_content).expect("Failed to write TOML");
    let path = file.path().to_str().unwrap();
    let config = load_toml_rules(path).expect("Should load TOML config");
    assert!(!config.is_empty());
    assert_eq!(config[0].expected_mode, 0o644);
}
