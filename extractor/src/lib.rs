//! CodeQL Extractor for Solidity - Library
//!
//! This crate provides the core functionality for extracting Solidity
//! source code into CodeQL databases.

pub mod codegen;
pub mod extraction;
pub mod schema;
pub mod trap;

pub use extraction::Extractor;
pub use trap::{Compression, Label, TrapValue, TrapWriter};
