# CodeQL Solidity

[![Test](https://github.com/lucasallan/codeql-solidity/actions/workflows/test.yml/badge.svg)](https://github.com/lucasallan/codeql-solidity/actions/workflows/test.yml)
[![Release](https://github.com/lucasallan/codeql-solidity/actions/workflows/release.yml/badge.svg)](https://github.com/lucasallan/codeql-solidity/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

CodeQL extractor and queries for Solidity smart contract security analysis.

## Features

- Tree-sitter based Solidity parsing
- Dataflow and taint tracking
- Call graph and inheritance analysis

## Installation

### Download CodeQL Packs

```bash
codeql pack download lucasallan/solidity-all
codeql pack download lucasallan/solidity-queries
```

### Download Extractor

Download from [Releases](https://github.com/lucasallan/codeql-solidity/releases)

## Usage

```bash
# Create database
export CODEQL_EXTRACTOR_SOLIDITY_ROOT=/path/to/extractor-pack
codeql database create db --language=solidity --source-root=/path/to/contracts

# Run analysis
codeql database analyze db lucasallan/solidity-queries --format=sarif-latest --output=results.sarif
```

## Project Structure

```
codeql-solidity/
├── extractor/           # Rust extractor binary
├── ql/lib/              # QL library (lucasallan/solidity-all)
├── queries/             # Security queries (lucasallan/solidity-queries)
├── extractor-pack/      # CodeQL extractor configuration
└── tests/               # Test fixtures
```

## Building from Source

```bash
cd extractor
cargo build --release

# Generate schema and QL library
./target/release/codeql-extractor-solidity generate \
  --dbscheme ../ql/lib/solidity.dbscheme \
  --library ../ql/lib/codeql/solidity/ast/internal/TreeSitter.qll
```

## License

Apache-2.0
