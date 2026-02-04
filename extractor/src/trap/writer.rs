//! TRAP file writer for CodeQL database population.
//!
//! TRAP (Tracing Data) files contain relational tuples that the CodeQL CLI
//! imports into a database. This writer generates valid TRAP syntax.
//!
//! IMPORTANT: Labels must be defined before they can be used in tuples.
//! - Fresh labels: `#prefix_id = *`
//! - Key labels: `@"content" = @"content"` (self-referential for files/folders)

use super::{Compression, Label, LabelGenerator};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::path::Path;

/// A value in a TRAP tuple.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TrapValue {
    /// A label reference (e.g., #1234)
    Label(Label),
    /// A string value (will be quoted and escaped)
    String(String),
    /// An integer value
    Int(i64),
    /// An unsigned integer value
    UInt(u64),
    /// A floating point value
    Float(f64),
}

impl TrapValue {
    /// Format this value for TRAP output.
    fn format(&self) -> String {
        match self {
            TrapValue::Label(l) => l.to_string(),
            TrapValue::String(s) => format!("\"{}\"", Self::escape_string(s)),
            TrapValue::Int(i) => i.to_string(),
            TrapValue::UInt(u) => u.to_string(),
            TrapValue::Float(f) => f.to_string(),
        }
    }

    /// Escape special characters in a string for TRAP format.
    /// In TRAP, double quotes are escaped by doubling them (""),
    /// and backslashes are escaped by doubling them (\\).
    fn escape_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => result.push_str("\"\""), // TRAP uses doubled quotes, not backslash
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                '\0' => result.push_str("\\0"),
                c if c.is_control() => {
                    result.push_str(&format!("\\x{:02x}", c as u32));
                }
                c => result.push(c),
            }
        }
        result
    }
}

/// A TRAP table entry (a single tuple).
#[derive(Debug, Clone)]
pub struct TrapEntry {
    /// Table name
    pub table: String,
    /// Column values
    pub values: Vec<TrapValue>,
}

impl TrapEntry {
    /// Create a new TRAP entry.
    pub fn new(table: impl Into<String>, values: Vec<TrapValue>) -> Self {
        TrapEntry {
            table: table.into(),
            values,
        }
    }

    /// Format this entry as a TRAP line.
    fn format(&self) -> String {
        let values: Vec<String> = self.values.iter().map(|v| v.format()).collect();
        format!("{}({})", self.table, values.join(", "))
    }
}

/// A label definition in TRAP format.
#[derive(Debug, Clone)]
pub enum LabelDef {
    /// Fresh label: `#id=*`
    Fresh(Label),
    /// Key label: `#id=@"key"` (numeric label assigned to a key)
    Key { numeric: Label, key: Label },
}

impl LabelDef {
    /// Format this label definition for TRAP output.
    /// Note: TRAP format requires no spaces around '=' in label definitions
    fn format(&self) -> String {
        match self {
            LabelDef::Fresh(l) => format!("{}=*", l),
            LabelDef::Key { numeric, key } => format!("{}={}", numeric, key),
        }
    }
}

/// TRAP file writer.
///
/// Collects TRAP entries and writes them to a file with optional compression.
/// Properly tracks label definitions to ensure they are defined before use.
#[derive(Default)]
pub struct TrapWriter {
    /// Label generator for this file
    labels: LabelGenerator,
    /// Label definitions (must be written before tuples)
    label_defs: Vec<LabelDef>,
    /// Set of already-defined labels (to avoid duplicates)
    defined_labels: HashSet<String>,
    /// Collected entries
    entries: Vec<TrapEntry>,
    /// Comments to include in output
    comments: Vec<String>,
    /// Cache for string labels (deduplication)
    string_cache: HashMap<String, Label>,
}

impl TrapWriter {
    /// Create a new TRAP writer for the given file.
    pub fn new(file_path: &str) -> Self {
        TrapWriter {
            labels: LabelGenerator::new(file_path),
            label_defs: Vec::new(),
            defined_labels: HashSet::new(),
            entries: Vec::new(),
            comments: Vec::new(),
            string_cache: HashMap::new(),
        }
    }

    /// Get a reference to the label generator.
    #[allow(dead_code)]
    pub fn labels(&self) -> &LabelGenerator {
        &self.labels
    }

    /// Generate a fresh label and define it.
    pub fn fresh_label(&mut self) -> Label {
        let label = self.labels.fresh();
        self.define_fresh_label(&label);
        label
    }

    /// Define a fresh label (ensures it's only defined once).
    fn define_fresh_label(&mut self, label: &Label) {
        let key = label.as_str().to_string();
        if !self.defined_labels.contains(&key) {
            self.defined_labels.insert(key);
            self.label_defs.push(LabelDef::Fresh(label.clone()));
        }
    }

    /// Define a key label (ensures it's only defined once).
    /// Creates a numeric label that references the key.
    fn define_key_label(&mut self, key_label: &Label) -> Label {
        let key_str = key_label.as_str().to_string();
        if let Some(existing) = self.string_cache.get(&key_str) {
            return existing.clone();
        }

        // Create a fresh numeric label for this key
        let numeric = self.labels.fresh();
        self.label_defs.push(LabelDef::Key {
            numeric: numeric.clone(),
            key: key_label.clone(),
        });
        self.defined_labels.insert(key_str.clone());
        self.string_cache.insert(key_str, numeric.clone());
        numeric
    }

    /// Get or create a label for a string value.
    /// Uses caching to deduplicate identical strings.
    #[allow(dead_code)]
    pub fn string_label(&mut self, s: &str) -> Label {
        if let Some(label) = self.string_cache.get(s) {
            return label.clone();
        }

        let key_label = self.labels.key(s);

        self.define_key_label(&key_label)
    }

    /// Add a comment to the output.
    #[allow(dead_code)]
    pub fn comment(&mut self, text: impl Into<String>) {
        self.comments.push(text.into());
    }

    /// Emit a TRAP entry.
    pub fn emit(&mut self, table: impl Into<String>, values: Vec<TrapValue>) {
        self.entries.push(TrapEntry::new(table, values));
    }

    /// Emit a tuple with the given label as the first value.
    #[allow(dead_code)]
    pub fn emit_with_label(
        &mut self,
        table: impl Into<String>,
        label: Label,
        values: Vec<TrapValue>,
    ) {
        let mut all_values = vec![TrapValue::Label(label)];
        all_values.extend(values);
        self.emit(table, all_values);
    }

    /// Emit a file entry and return its label.
    pub fn emit_file(&mut self, path: &str) -> Label {
        let key_label = self.labels.key(path);
        let numeric_label = self.define_key_label(&key_label);
        self.emit(
            "files",
            vec![
                TrapValue::Label(numeric_label.clone()),
                TrapValue::String(path.to_string()),
            ],
        );
        numeric_label
    }

    /// Emit a folder entry and return its label.
    pub fn emit_folder(&mut self, path: &str) -> Label {
        let key_label = self.labels.key(path);
        let numeric_label = self.define_key_label(&key_label);
        self.emit(
            "folders",
            vec![
                TrapValue::Label(numeric_label.clone()),
                TrapValue::String(path.to_string()),
            ],
        );
        numeric_label
    }

    /// Emit a location entry and return its label.
    pub fn emit_location(
        &mut self,
        file_label: &Label,
        start_line: u32,
        start_col: u32,
        end_line: u32,
        end_col: u32,
    ) -> Label {
        let label = self.fresh_label();
        self.emit(
            "locations_default",
            vec![
                TrapValue::Label(label.clone()),
                TrapValue::Label(file_label.clone()),
                TrapValue::UInt(start_line as u64),
                TrapValue::UInt(start_col as u64),
                TrapValue::UInt(end_line as u64),
                TrapValue::UInt(end_col as u64),
            ],
        );
        label
    }

    /// Get the number of entries written.
    #[allow(dead_code)]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Format all entries to a string.
    pub fn format(&self) -> String {
        let mut output = String::new();

        // Write header comment
        writeln!(
            output,
            "// CodeQL TRAP file generated by codeql-extractor-solidity"
        )
        .unwrap();
        writeln!(output).unwrap();

        // Write user comments
        for comment in &self.comments {
            writeln!(output, "// {}", comment).unwrap();
        }
        if !self.comments.is_empty() {
            writeln!(output).unwrap();
        }

        // Write label definitions FIRST (required before use in tuples)
        if !self.label_defs.is_empty() {
            writeln!(output, "// Label definitions").unwrap();
            for label_def in &self.label_defs {
                writeln!(output, "{}", label_def.format()).unwrap();
            }
            writeln!(output).unwrap();
        }

        // Write tuple entries
        for entry in &self.entries {
            writeln!(output, "{}", entry.format()).unwrap();
        }

        output
    }

    /// Write to a file with the specified compression.
    pub fn write_to_file(&self, path: &Path, compression: Compression) -> io::Result<()> {
        let trap_path = path.with_extension(compression.extension().trim_start_matches('.'));
        let mut writer = compression.create_writer(&trap_path)?;
        writer.write_all(self.format().as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    /// Write to a writer.
    #[allow(dead_code)]
    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.format().as_bytes())?;
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trap_entry_format() {
        let entry = TrapEntry::new(
            "test_table",
            vec![
                TrapValue::Label(Label::new("#1")),
                TrapValue::String("hello".to_string()),
                TrapValue::Int(42),
            ],
        );
        assert_eq!(entry.format(), "test_table(#1, \"hello\", 42)");
    }

    #[test]
    fn test_string_escaping() {
        let entry = TrapEntry::new(
            "strings",
            vec![TrapValue::String("hello\nworld\"test".to_string())],
        );
        // TRAP uses doubled quotes for escaping, not backslash-quote
        assert_eq!(entry.format(), "strings(\"hello\\nworld\"\"test\")");
    }

    #[test]
    fn test_trap_writer_emit() {
        let mut writer = TrapWriter::new("/test/file.sol");
        writer.emit("test", vec![TrapValue::Int(1), TrapValue::Int(2)]);
        assert_eq!(writer.entry_count(), 1);
    }

    #[test]
    fn test_file_emission() {
        let mut writer = TrapWriter::new("/test/file.sol");
        let label = writer.emit_file("/test/file.sol");
        // emit_file returns a numeric label (#NNN) that references the key label (@"path")
        // The definition in TRAP will be: #NNN=@"/test/file.sol"
        assert!(
            label.as_str().starts_with("#"),
            "Expected numeric label, got: {}",
            label.as_str()
        );
    }

    #[test]
    fn test_location_emission() {
        let mut writer = TrapWriter::new("/test/file.sol");
        let file_label = writer.emit_file("/test/file.sol");
        let loc_label = writer.emit_location(&file_label, 1, 1, 1, 10);
        assert!(loc_label.as_str().starts_with("#"));
    }

    #[test]
    fn test_label_definitions_in_output() {
        let mut writer = TrapWriter::new("/test/file.sol");
        let file_label = writer.emit_file("/test/file.sol");
        let loc_label = writer.emit_location(&file_label, 1, 1, 1, 10);

        let output = writer.format();

        // File label should be defined as #NNN=@"path"
        let file_def_pos = output.find(&format!("{}=@\"/test/file.sol\"", file_label));
        let loc_def_pos = output.find(&format!("{}=*", loc_label));
        let tuple_pos = output.find("files(");

        assert!(
            file_def_pos.is_some(),
            "File label definition not found in output:\n{}",
            output
        );
        assert!(loc_def_pos.is_some(), "Location label definition not found");
        assert!(tuple_pos.is_some(), "Tuple not found");

        // Definitions must come before tuples
        assert!(
            file_def_pos.unwrap() < tuple_pos.unwrap(),
            "File label definition must come before tuple"
        );
        assert!(
            loc_def_pos.unwrap() < tuple_pos.unwrap(),
            "Location label definition must come before tuple"
        );
    }
}
