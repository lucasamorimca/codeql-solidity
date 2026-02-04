/**
 * Base AST node class for Solidity.
 *
 * This module provides the foundational AstNode class that all
 * other AST node types extend.
 */

private import codeql.solidity.ast.internal.TreeSitter

/**
 * An AST node in a Solidity source file.
 */
class AstNode extends Solidity::AstNode {
  /**
   * Gets the file containing this AST node.
   */
  override File getFile() { result = super.getFile() }

  /**
   * Gets the location of this AST node.
   */
  override Location getLocation() { result = super.getLocation() }

  /**
   * Gets the parent of this AST node in the AST, if any.
   */
  override AstNode getParent() { result = super.getParent() }

  /**
   * Gets a child of this AST node.
   */
  override AstNode getAChild() { result = super.getAChild() }

  /**
   * Gets the i-th child of this AST node (0-indexed).
   */
  override AstNode getChild(int i) { result = super.getChild(i) }
}
