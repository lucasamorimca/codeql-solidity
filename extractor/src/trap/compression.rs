//! TRAP file compression support.
//!
//! CodeQL supports both gzip-compressed and uncompressed TRAP files.
//! Gzip is the default for production use; uncompressed is useful for debugging.

use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Compression mode for TRAP files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// Gzip compression (default, recommended for production)
    #[default]
    Gzip,
    /// No compression (useful for debugging)
    None,
}

impl Compression {
    /// Parse compression mode from environment variable.
    ///
    /// Reads from `CODEQL_EXTRACTOR_SOLIDITY_OPTION_TRAP_COMPRESSION`.
    /// Valid values: "gzip" (default), "none"
    pub fn from_env() -> Self {
        match std::env::var("CODEQL_EXTRACTOR_SOLIDITY_OPTION_TRAP_COMPRESSION")
            .as_deref()
            .unwrap_or("gzip")
        {
            "none" => Compression::None,
            _ => Compression::Gzip,
        }
    }

    /// Parse compression mode from string representation.
    #[allow(dead_code)]
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "none" => Compression::None,
            _ => Compression::Gzip,
        }
    }

    /// Get the file extension for this compression mode.
    pub fn extension(&self) -> &'static str {
        match self {
            Compression::Gzip => ".trap.gz",
            Compression::None => ".trap",
        }
    }

    /// Create a writer for the given file path with appropriate compression.
    pub fn create_writer(&self, path: &Path) -> io::Result<Box<dyn Write>> {
        let file = File::create(path)?;
        let buffered = BufWriter::new(file);

        match self {
            Compression::Gzip => {
                let encoder = GzEncoder::new(buffered, GzCompression::default());
                Ok(Box::new(encoder))
            }
            Compression::None => Ok(Box::new(buffered)),
        }
    }
}

impl std::str::FromStr for Compression {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gzip" | "gz" => Ok(Compression::Gzip),
            "none" | "uncompressed" => Ok(Compression::None),
            _ => Err(format!(
                "Unknown compression mode: {}. Valid values: gzip, none",
                s
            )),
        }
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Compression::Gzip => write!(f, "gzip"),
            Compression::None => write!(f, "none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_extension() {
        assert_eq!(Compression::Gzip.extension(), ".trap.gz");
        assert_eq!(Compression::None.extension(), ".trap");
    }

    #[test]
    fn test_compression_from_str() {
        assert_eq!("gzip".parse::<Compression>().unwrap(), Compression::Gzip);
        assert_eq!("none".parse::<Compression>().unwrap(), Compression::None);
        assert!("invalid".parse::<Compression>().is_err());
    }
}
