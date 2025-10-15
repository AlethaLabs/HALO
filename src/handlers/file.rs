use std::fs;
use std::path::PathBuf;
use indexmap::IndexMap;

use crate::types::{DataList, DataMap};

/// Reads and parses file contents into structured data format
/// Expects colon-separated key-value pairs with blank lines as record separators
pub fn handle_file(file: Option<PathBuf>) -> DataList {
    // println!("DEBUG: trying to read {:?}", paths);
    let content = if let Some(path) = file {
        fs::read_to_string(path)
    } else {
        Ok(String::new())
    };

    let mut data: DataList = Vec::new();
    let mut current_map: DataMap = IndexMap::new();

    for line in content.unwrap_or_default().lines() {
        if line.trim().is_empty() {
            if !current_map.is_empty() {
                data.push(current_map.clone());
                current_map.clear();
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            current_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    if !current_map.is_empty() {
        data.push(current_map);
    }

    data
}