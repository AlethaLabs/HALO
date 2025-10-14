//! Parse command handler
//!
//! Handles file parsing and rendering functionality.

use crate::handlers::file::handle_file;
use alhalo::{ParsedData, Renderable};
use alhalo::render_output::OutputFormat;
use std::path::PathBuf;

// Handler for the `parse` command
//
// Parses the specified file and renders output in the selected format
// Optionally stores output to a file
pub fn handle_parse(
    file: &Option<PathBuf>,
    format: &Option<String>,
    line: &Option<Vec<String>>,
    store: &Option<PathBuf>,
) {
    let data = handle_file(file.as_ref().map(|p| p.to_owned()));
    let filter_keys = line.as_ref().cloned().unwrap_or_default();
    let parsed_data = ParsedData::with_filter(data, filter_keys);
    
    let output_format = OutputFormat::from_str(format.as_deref());
    match parsed_data.render(output_format) {
        Ok(output) => {
            print!("{}", output);
            if let Some(path) = store {
                if let Err(e) = std::fs::write(path, &output) {
                    eprintln!("Failed to store output: {}", e);
                } else {
                    println!("Output stored to {}", path.display());
                }
            }
        }
        Err(e) => eprintln!("Error rendering output: {}", e),
    }
}