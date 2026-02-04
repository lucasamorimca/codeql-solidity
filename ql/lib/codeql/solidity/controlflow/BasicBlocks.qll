/**
 * Provides classes for working with basic blocks in the control flow graph.
 *
 * A basic block is a maximal sequence of control flow nodes such that:
 * - The first node is the only entry point
 * - The last node is the only exit point
 * - All other nodes have exactly one predecessor and one successor
 */

private import codeql.solidity.ast.internal.TreeSitter
private import internal.ControlFlowGraphImpl

/**
 * A basic block in the control flow graph.
 *
 * A basic block is identified by its first node.
 */
class BasicBlock extends CfgNode {
  BasicBlock() {
    // A node starts a basic block if:
    // 1. It's a function entry point
    this instanceof EntryNode
    or
    // 2. It has no predecessors (unreachable, but still a block)
    not successor(_, this) and not this instanceof EntryNode
    or
    // 3. It has multiple predecessors
    strictcount(CfgNode pred | successor(pred, this)) > 1
    or
    // 4. Its predecessor has multiple successors
    exists(CfgNode pred |
      successor(pred, this) and
      strictcount(CfgNode other | successor(pred, other)) > 1
    )
  }

  /** Gets a successor basic block. */
  BasicBlock getASuccessor() {
    exists(CfgNode last |
      last = this.getLastNode() and
      successor(last, result)
    )
    or
    exists(CfgNode last, CfgNode mid |
      last = this.getLastNode() and
      successor(last, mid) and
      not mid instanceof BasicBlock and
      result = getBasicBlock(mid)
    )
  }

  /** Gets a predecessor basic block. */
  BasicBlock getAPredecessor() { result.getASuccessor() = this }

  /** Gets the unique predecessor if there is exactly one. */
  BasicBlock getUniquePredecessor() {
    result = this.getAPredecessor() and
    strictcount(this.getAPredecessor()) = 1
  }

  /** Gets the i-th node in this basic block (0-indexed). */
  CfgNode getNode(int i) {
    i = 0 and result = this
    or
    i > 0 and
    exists(CfgNode prev |
      prev = this.getNode(i - 1) and
      successor(prev, result) and
      not result instanceof BasicBlock
    )
  }

  /** Gets any node in this basic block. */
  CfgNode getANode() { result = this.getNode(_) }

  /** Gets the last node in this basic block. */
  CfgNode getLastNode() {
    result = this.getANode() and
    (
      // Has no successor
      not successor(result, _)
      or
      // Or successor is a different basic block
      exists(CfgNode s | successor(result, s) and s instanceof BasicBlock)
      or
      // Or has multiple successors
      strictcount(CfgNode s | successor(result, s)) > 1
    )
  }

  /** Gets the first node in this basic block (same as the block itself). */
  CfgNode getFirstNode() { result = this }

  /** Gets the number of nodes in this basic block. */
  int length() { result = count(this.getANode()) }

  /** Holds if this basic block is reachable from the entry point. */
  predicate isReachable() {
    this instanceof EntryNode
    or
    this.getAPredecessor().isReachable()
  }

  /** Gets the enclosing function entry node. */
  EntryNode getEnclosingEntry() {
    this = result
    or
    exists(BasicBlock pred |
      pred = this.getAPredecessor() and
      result = pred.getEnclosingEntry()
    )
  }

  /** Gets a string representation of this basic block. */
  override string toString() { result = "BasicBlock at " + this.getLocation().toString() }
}

/**
 * Gets the basic block containing the given CFG node.
 */
BasicBlock getBasicBlock(CfgNode node) {
  result = node
  or
  not node instanceof BasicBlock and
  exists(CfgNode pred |
    successor(pred, node) and
    result = getBasicBlock(pred)
  )
}

/**
 * Extension to CfgNode for basic block access.
 */
private class CfgNodeExt extends CfgNode {
  /** Gets the basic block containing this node. */
  BasicBlock getBasicBlock() { result = getBasicBlock(this) }
}

/**
 * An entry basic block (first block in a function).
 */
class EntryBasicBlock extends BasicBlock {
  EntryBasicBlock() { this instanceof EntryNode }
}

/**
 * An exit basic block (last block in a function).
 */
class ExitBasicBlock extends BasicBlock {
  ExitBasicBlock() {
    exists(EntryNode entry |
      getAnExitNode(entry) = this.getANode()
    )
  }
}

/**
 * A basic block with multiple successors (branch point).
 */
class ConditionBasicBlock extends BasicBlock {
  ConditionBasicBlock() {
    strictcount(this.getASuccessor()) > 1
  }

  /** Gets the true successor (for if/while conditions). */
  BasicBlock getTrueSuccessor() {
    // This is approximate - would need completion info for precision
    result = this.getASuccessor() and
    result != this.getFalseSuccessor()
  }

  /** Gets the false successor (for if/while conditions). */
  BasicBlock getFalseSuccessor() {
    result = this.getASuccessor() and
    result != this.getTrueSuccessor()
  }
}

/**
 * A basic block with multiple predecessors (join point).
 */
class JoinBasicBlock extends BasicBlock {
  JoinBasicBlock() {
    strictcount(this.getAPredecessor()) > 1
  }
}
