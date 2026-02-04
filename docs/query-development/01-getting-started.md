# Getting Started with CodeQL for Solidity

This guide walks you through setting up CodeQL for Solidity analysis and writing your first query.

## Prerequisites

- **CodeQL CLI** (v2.15.0+): [Download](https://github.com/github/codeql-cli-binaries/releases)
- **VS Code** + CodeQL extension (recommended)
- **Git** for cloning the repository

## Installation

### 1. Install CodeQL CLI

```bash
# Download and extract CodeQL CLI
# Add to PATH
export PATH="$PATH:/path/to/codeql"

# Verify installation
codeql version
```

### 2. Clone codeql-solidity

```bash
git clone https://github.com/anthropics/codeql-solidity.git
cd codeql-solidity
```

### 3. Configure QL Search Path

Create or update `~/.config/codeql/config`:

```yaml
--search-path=/path/to/codeql-solidity/ql/lib
```

Or use the `--search-path` flag with each command.

### 4. VS Code Setup (Recommended)

1. Install "CodeQL" extension from marketplace
2. Open codeql-solidity folder
3. CodeQL extension auto-detects the QL pack

## Creating Your First Database

### From a Solidity Project

```bash
# Navigate to your Solidity project
cd /path/to/solidity-project

# Create database
codeql database create solidity-db \
  --language=solidity \
  --source-root=. \
  --overwrite

# Database created at ./solidity-db
```

### From Test Fixtures

```bash
cd /path/to/codeql-solidity

# Create database from test fixtures
codeql database create test-db \
  --language=solidity \
  --source-root=tests/fixtures \
  --overwrite
```

## Your First Query

Create a file `FindPublicFunctions.ql`:

```ql
/**
 * @name Find public functions
 * @description Lists all public functions in Solidity contracts
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/find-public-functions
 * @tags analysis solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Holds if function has public visibility.
 */
predicate isPublic(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode v |
    v.getParent() = func and
    v.getValue() = "public"
  )
}

from Solidity::FunctionDefinition func
where isPublic(func)
select func, "Public function: " + getFunctionName(func)
```

### Query Structure Explained

| Section | Purpose |
|---------|---------|
| Metadata (`@name`, `@id`, etc.) | Query identification and display |
| `import` | Load required libraries |
| Helper predicates | Reusable logic |
| `from-where-select` | Main query logic |

### Required Metadata Fields

| Field | Description | Example |
|-------|-------------|---------|
| `@name` | Human-readable name | `Find public functions` |
| `@description` | What query detects | `Lists all public functions` |
| `@kind` | Result type | `problem`, `path-problem`, `metric` |
| `@id` | Unique identifier | `solidity/find-public-functions` |

## Running Queries

### Command Line

```bash
# Run query against database
codeql query run FindPublicFunctions.ql \
  --database=solidity-db \
  --output=results.bqrs

# Decode results
codeql bqrs decode results.bqrs --format=csv
```

### VS Code

1. Open query file
2. Right-click → "CodeQL: Run Query on Selected Database"
3. Results appear in CodeQL panel

### Quick Eval (VS Code)

1. Select expression in query
2. Right-click → "CodeQL: Quick Evaluation"
3. See intermediate results

## Query Development Workflow

```
1. Write query → 2. Quick Eval subexpressions → 3. Run full query → 4. Refine
```

**Tips:**
- Start with simple patterns, add complexity
- Use Quick Eval to debug predicates
- Check AST Viewer for node structure
- Test on small databases first

## Example: Find External Calls

```ql
/**
 * @name Find external calls
 * @description Lists all low-level external calls
 * @kind problem
 * @problem.severity warning
 * @id solidity/find-external-calls
 * @tags security solidity
 */

import codeql.solidity.ast.internal.TreeSitter

from Solidity::CallExpression call, Solidity::MemberExpression member
where
  member = call.getFunction() and
  member.getProperty().(Solidity::AstNode).getValue() in ["call", "delegatecall", "staticcall"]
select call, "Low-level external call: " + member.getProperty().(Solidity::AstNode).getValue()
```

## Troubleshooting

### Database Creation Fails

```bash
# Check extractor is installed
codeql resolve languages

# Should show: solidity
```

### Query Compilation Errors

- Verify import paths match library structure
- Check predicate signatures
- Ensure metadata format is correct

### No Results

- Verify database contains expected files
- Check predicates with Quick Eval
- Add intermediate `select` statements

## Next Steps

- [Core Concepts](02-core-concepts.md) - AST hierarchy and navigation
- [Control Flow](03-control-flow.md) - CFG analysis
- [Data Flow](04-data-flow.md) - Taint tracking
- [Security Queries](06-writing-security-queries.md) - Vulnerability detection
