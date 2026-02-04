/**
 * CodeQL library for Solidity smart contract analysis.
 *
 * This is the main entry point for importing Solidity analysis capabilities.
 */

// Re-export TreeSitter types (includes module Solidity)
import codeql.solidity.ast.internal.TreeSitter

// AST abstraction modules
import codeql.solidity.ast.AstNode
import codeql.solidity.ast.Expr
import codeql.solidity.ast.Stmt
import codeql.solidity.ast.Function
import codeql.solidity.ast.Contract

// Control Flow Graph
import codeql.solidity.controlflow.ControlFlowGraph

// Data Flow and Taint Tracking
import codeql.solidity.dataflow.DataFlow
import codeql.solidity.dataflow.TaintTracking
