//! TRAP file generation module for CodeQL.
//!
//! TRAP (Tracing Data) is the intermediate file format used by CodeQL
//! to populate databases. This module provides a custom implementation
//! with no external dependencies.

mod compression;
mod label;
mod writer;

pub use compression::Compression;
pub use label::{Label, LabelGenerator};
pub use writer::{TrapValue, TrapWriter};
