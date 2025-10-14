use indexmap::IndexMap;

/// A deterministic map of key-value pairs parsed from a file.
///
/// Using `IndexMap` instead of `HashMap` avoids randomizing file contents, ensuring stable output order.
pub type DataMap = IndexMap<String, String>;

/// A list of parsed data maps, representing structured file contents.
pub type DataList = Vec<DataMap>;
