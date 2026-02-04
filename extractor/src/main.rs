//! CodeQL Extractor for Solidity
//!
//! This extractor parses Solidity source files using tree-sitter and generates
//! TRAP files for CodeQL database population.

mod codegen;
mod extraction;
mod schema;
mod trap;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::trap::Compression;

/// CodeQL Extractor for Solidity smart contracts
#[derive(Parser)]
#[command(name = "codeql-extractor-solidity")]
#[command(author = "SafeStack AI")]
#[command(version)]
#[command(about = "Extract Solidity source code into CodeQL databases")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract Solidity source files to TRAP
    Extract {
        /// File containing list of source files to extract (one per line)
        #[arg(long)]
        file_list: PathBuf,

        /// Output directory for TRAP files
        #[arg(long, env = "CODEQL_EXTRACTOR_SOLIDITY_TRAP_DIR")]
        trap_dir: PathBuf,

        /// Output directory for source archive
        #[arg(long, env = "CODEQL_EXTRACTOR_SOLIDITY_SOURCE_ARCHIVE_DIR")]
        source_archive_dir: PathBuf,

        /// Compression mode for TRAP files (gzip or none)
        #[arg(long, default_value = "gzip")]
        compression: String,

        /// Number of threads for parallel extraction
        #[arg(long, short = 'j')]
        threads: Option<usize>,
    },

    /// Generate database schema and QL library from tree-sitter grammar
    Generate {
        /// Output path for the .dbscheme file
        #[arg(long)]
        dbscheme: PathBuf,

        /// Output path for the TreeSitter.qll file
        #[arg(long)]
        library: PathBuf,
    },

    /// Automatically find and extract all Solidity files in the current directory
    Autobuild {
        /// Root directory to search for .sol files
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Output directory for TRAP files
        #[arg(long, env = "CODEQL_EXTRACTOR_SOLIDITY_TRAP_DIR")]
        trap_dir: PathBuf,

        /// Output directory for source archive
        #[arg(long, env = "CODEQL_EXTRACTOR_SOLIDITY_SOURCE_ARCHIVE_DIR")]
        source_archive_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("CODEQL_EXTRACTOR_SOLIDITY_LOG")
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Extract {
            file_list,
            trap_dir,
            source_archive_dir,
            compression,
            threads,
        } => {
            let compression = compression.parse::<Compression>().unwrap_or_default();

            info!("Extracting from file list: {}", file_list.display());

            extraction::run(extraction::ExtractOptions {
                file_list,
                trap_dir,
                source_archive_dir,
                compression,
                threads,
            })?;
        }

        Commands::Generate { dbscheme, library } => {
            info!("Generating schema: {}", dbscheme.display());
            info!("Generating library: {}", library.display());

            schema::generate(&dbscheme)?;
            codegen::generate(&library)?;
        }

        Commands::Autobuild {
            root,
            trap_dir,
            source_archive_dir,
        } => {
            info!("Autobuilding from: {}", root.display());

            extraction::autobuild(extraction::AutobuildOptions {
                root,
                trap_dir,
                source_archive_dir,
            })?;
        }
    }

    Ok(())
}
