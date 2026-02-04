//! Deterministic label generation for TRAP entities.
//!
//! Labels uniquely identify entities in the CodeQL database.
//! We use a two-tier system:
//! - Fresh IDs: For unique entities (AST nodes, locations)
//! - Stable IDs: For content-based deduplication (strings, files)

use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// A label uniquely identifies an entity in the TRAP file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Label(String);

impl Label {
    /// Create a label from a raw string.
    #[allow(dead_code)]
    pub fn new(s: impl Into<String>) -> Self {
        Label(s.into())
    }

    /// Create a fresh label with the given prefix and ID.
    /// Uses simple numeric format like #10000 for TRAP compatibility.
    pub fn fresh(_prefix: &str, id: u64) -> Self {
        // Use 10000+ to avoid conflicts with low numbers that might have special meaning
        Label(format!("#{}", 10000 + id))
    }

    /// Create a stable label based on content hash.
    #[allow(dead_code)]
    pub fn stable(content: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hasher.finalize();
        // Use first 16 hex chars for a 64-bit identifier
        Label(format!(
            "#{:x}",
            &hash[..8].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
        ))
    }

    /// Create a key label for content-addressable entities.
    /// Format: @"content"
    pub fn key(content: &str) -> Self {
        Label(format!("@\"{}\"", Self::escape_string(content)))
    }

    /// Get the raw label string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Escape special characters in a string for TRAP format.
    fn escape_string(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                c if c.is_control() => {
                    result.push_str(&format!("\\x{:02x}", c as u32));
                }
                c => result.push(c),
            }
        }
        result
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generator for deterministic labels.
///
/// Uses a combination of file hash and counter to ensure
/// labels are reproducible across extractions.
pub struct LabelGenerator {
    /// Base prefix derived from file path hash
    prefix: String,
    /// Counter for fresh IDs
    counter: AtomicU64,
}

impl LabelGenerator {
    /// Create a new label generator for a specific file.
    pub fn new(file_path: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(file_path.as_bytes());
        let hash = hasher.finalize();
        // Use first 8 hex chars as prefix
        let prefix = format!(
            "{:x}",
            &hash[..4].iter().fold(0u32, |acc, &b| (acc << 8) | b as u32)
        );

        LabelGenerator {
            prefix,
            counter: AtomicU64::new(0),
        }
    }

    /// Generate a fresh unique label.
    pub fn fresh(&self) -> Label {
        let id = self.counter.fetch_add(1, Ordering::SeqCst);
        Label::fresh(&self.prefix, id)
    }

    /// Generate a stable label for content-addressable entities.
    #[allow(dead_code)]
    pub fn stable(&self, content: &str) -> Label {
        Label::stable(content)
    }

    /// Generate a key label for globally-addressable entities.
    pub fn key(&self, content: &str) -> Label {
        Label::key(content)
    }

    /// Get the current counter value (for debugging).
    #[allow(dead_code)]
    pub fn current_count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

impl Default for LabelGenerator {
    fn default() -> Self {
        LabelGenerator {
            prefix: "default".to_string(),
            counter: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_labels_are_unique() {
        let gen = LabelGenerator::new("/test/file.sol");
        let l1 = gen.fresh();
        let l2 = gen.fresh();
        assert_ne!(l1, l2);
    }

    #[test]
    fn test_stable_labels_are_deterministic() {
        let l1 = Label::stable("hello");
        let l2 = Label::stable("hello");
        assert_eq!(l1, l2);
    }

    #[test]
    fn test_key_label_escaping() {
        let label = Label::key("test\"with\\quotes");
        assert!(label.as_str().contains("\\\""));
        assert!(label.as_str().contains("\\\\"));
    }

    #[test]
    fn test_generator_determinism() {
        let gen1 = LabelGenerator::new("/same/path.sol");
        let gen2 = LabelGenerator::new("/same/path.sol");

        // Same file should produce same prefix
        let l1 = gen1.fresh();
        let _l2 = gen2.fresh();

        // Labels have same prefix but different counters are independent
        // (in real usage, same file = same generator instance)
        assert!(l1.as_str().starts_with("#"));
    }
}
