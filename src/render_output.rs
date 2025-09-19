//! Output rendering utilities for HALO.
//!
//! This module provides functions to render audit and parsed data in multiple formats:
//! - Pretty-printed JSON
//! - CSV (with optional column filtering)
//! - Human-readable text blocks
//!
//! Used by the CLI and macro system to display results in a user-friendly way.

use indexmap::IndexMap;
use serde::Serialize;
use serde_json;
use std::io;

/// A deterministic map of key-value pairs parsed from a file.
///
/// Using `IndexMap` instead of `HashMap` avoids randomizing file contents, ensuring stable output order.
pub type DataMap = IndexMap<String, String>;

/// A list of parsed data maps, representing structured file contents.
pub type DataList = Vec<DataMap>;
/// Renders any serializable data as pretty-printed JSON.
///
/// # Arguments
/// * `data` - Reference to a serializable data structure.
///
/// # Returns
/// * `io::Result<String>` containing the pretty-printed JSON string or an error.
pub fn render_json<T: Serialize>(data: &T) -> io::Result<String> {
    let s =
        serde_json::to_string_pretty(data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(s + "\n")
}

/// Renders a list of data maps as CSV.
///
/// # Arguments
/// * `data` - List of data maps to render.
/// * `line` - List of keys to use as CSV headers (column filter). If empty, uses all keys from the first block.
///
/// # Returns
/// * `io::Result<String>` containing the CSV string or an error.
pub fn render_csv(data: &DataList, line: &[String]) -> io::Result<String> {
    let data = filter(data, line);

    let headers: Vec<String> = if !line.is_empty() {
        line.to_vec()
    } else if let Some(first) = data.first() {
        first.keys().cloned().collect()
    } else {
        Vec::new()
    };

    let mut out = String::new();
    if !headers.is_empty() {
        out.push_str(&headers.join(","));
        out.push('\n');
        for row in &data {
            let row_line: Vec<String> = headers
                .iter()
                .map(|h| row.get(h).cloned().unwrap_or_default())
                .collect();
            out.push_str(&row_line.join(","));
            out.push('\n');
        }
    }
    Ok(out)
}

/// Renders a list of data maps as pretty text blocks.
///
/// # Arguments
/// * `data` - List of data maps to render.
/// * `line` - List of keys to filter output. If empty, renders all keys.
///
/// # Returns
/// * `io::Result<String>` containing the formatted text or an error.
pub fn render_text(data: &DataList, line: &[String]) -> io::Result<String> {
    let data = filter(data, line);
    let mut out = String::new();
    for block in data {
        for (k, v) in block {
            out.push_str(&format!("  {}: {}\n", k, v));
        }
        out.push('\n');
    }
    Ok(out)
}

/// Filters a list of data maps by the given keys.
///
/// # Arguments
/// * `data` - List of data maps to filter.
/// * `line` - List of keys to include in the output. If empty, returns all data.
///
/// # Returns
/// * `DataList` containing only the filtered key-value pairs.
pub fn filter(data: &DataList, line: &[String]) -> DataList {
    if line.is_empty() {
        return data.clone();
    }
    data.iter()
        .map(|block| {
            let mut m = DataMap::new();
            for f in line {
                if let Some(val) = block.get(f) {
                    m.insert(f.clone(), val.clone());
                }
            }
            m
        })
        .collect()
}
