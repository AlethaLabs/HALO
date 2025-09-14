// Integration tests for output rendering in HALO
use halo::{DataList, DataMap, filter, render_csv, render_json, render_text};

fn sample_data() -> DataList {
    let mut map = DataMap::new();
    map.insert("key1".to_string(), "value1".to_string());
    map.insert("key2".to_string(), "value2".to_string());
    vec![map]
}

#[test]
fn test_render_json() {
    let data = sample_data();
    let json = render_json(&data).expect("Should render JSON");
    assert!(json.contains("key1"));
    assert!(json.contains("value1"));
}

#[test]
fn test_render_csv() {
    let data = sample_data();
    let csv =
        render_csv(&data, &["key1".to_string(), "key2".to_string()]).expect("Should render CSV");
    assert!(csv.contains("key1,key2"));
    assert!(csv.contains("value1,value2"));
}

#[test]
fn test_render_text() {
    let data = sample_data();
    let text = render_text(&data, &[]).expect("Should render text");
    assert!(text.contains("Block 0:"));
    assert!(text.contains("key1: value1"));
}

#[test]
fn test_filter() {
    let data = sample_data();
    let filtered = filter(&data, &["key1".to_string()]);
    assert_eq!(filtered[0].len(), 1);
    assert!(filtered[0].contains_key("key1"));
}
