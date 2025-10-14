//! Output rendering utilities for HALO.
//!
//! This module provides functions to render audit and parsed data in multiple formats:
//! - Pretty-printed JSON
//! - CSV (with optional column filtering)
//! - Human-readable text blocks
//! - Unified trait-based rendering for consistent output handling
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

/// Wrapper for parsed data that supports filtering and rendering
#[derive(Debug, Clone)]
pub struct ParsedData {
    pub data: DataList,
    pub filter_keys: Vec<String>,
}

impl ParsedData {
    pub fn new(data: DataList) -> Self {
        Self {
            data,
            filter_keys: Vec::new(),
        }
    }

    pub fn with_filter(data: DataList, filter_keys: Vec<String>) -> Self {
        Self { data, filter_keys }
    }

    /// Get the filtered data for serialization
    pub fn filtered_data(&self) -> DataList {
        filter(&self.data, &self.filter_keys)
    }
}

impl Serialize for ParsedData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.filtered_data().serialize(serializer)
    }
}

/// Supported output formats for CLI commands
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Csv,
    Text,
    Pretty,
}

impl OutputFormat {
    /// Parse format string into OutputFormat enum
    pub fn from_str(s: Option<&str>) -> Self {
        match s {
            Some("json") => Self::Json,
            Some("csv") => Self::Csv,
            Some("text") => Self::Text,
            _ => Self::Pretty,
        }
    }
}

/// Trait for types that can be rendered in multiple output formats
pub trait Renderable {
    /// Convert to DataList for CSV/text rendering
    fn to_datalist(&self) -> DataList;
    
    /// Custom pretty-print format (optional override)
    fn pretty_print(&self) -> String {
        "Output available in JSON, CSV, or text format.".to_string()
    }
    
    /// Render in the specified format
    fn render(&self, format: OutputFormat) -> io::Result<String>
    where
        Self: Serialize,
    {
        match format {
            OutputFormat::Json => render_json(&self),
            OutputFormat::Csv => render_csv(&self.to_datalist(), &[]),
            OutputFormat::Text => render_text(&self.to_datalist(), &[]),
            OutputFormat::Pretty => Ok(self.pretty_print()),
        }
    }
    
    /// Render and print to stdout with error handling
    fn render_and_print(&self, format: Option<&str>)
    where
        Self: Serialize,
    {
        let output_format = OutputFormat::from_str(format);
        match self.render(output_format) {
            Ok(output) => print!("{}", output),
            Err(e) => eprintln!("Error rendering output: {}", e),
        }
    }
}

impl Renderable for ParsedData {
    fn to_datalist(&self) -> DataList {
        self.filtered_data()
    }

    fn pretty_print(&self) -> String {
        let filtered_data = self.filtered_data();
        match render_text(&filtered_data, &[]) {
            Ok(output) => output,
            Err(_) => "Error rendering data".to_string(),
        }
    }
}

/// Implement Renderable for Vec<T> where T: Renderable
impl<T> Renderable for Vec<T>
where
    T: Renderable + Serialize,
{
    fn to_datalist(&self) -> DataList {
        self.iter()
            .flat_map(|item| item.to_datalist())
            .collect()
    }
    
    fn pretty_print(&self) -> String {
        if self.is_empty() {
            return "No results found.".to_string();
        }
        
        let mut output = String::new();
        output.push_str(&format!("Results Found:\n"));
        for item in self {
            output.push_str(&format!("  {}\n", item.pretty_print()));
        }
        output.push_str(&format!("\nTotal results: {}", self.len()));
        output
    }
}
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
