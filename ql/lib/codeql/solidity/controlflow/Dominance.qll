/**
 * Provides classes and predicates for computing dominance relationships
 * in the control flow graph.
 *
 * Dominance is a fundamental concept in control flow analysis:
 * - Node A dominates node B if every path from the entry to B goes through A
 * - Node A strictly dominates B if A dominates B and A != B
 * - Node A immediately dominates B if A strictly dominates B and there's no
 *   node C such that A strictly dominates C and C strictly dominates B
 *
 * Post-dominance is the dual:
 * - Node A post-dominates B if every path from B to exit goes through A
 */

private import codeql.solidity.ast.internal.TreeSitter
private import internal.ControlFlowGraphImpl
private import BasicBlocks

/**
 * Holds if `dominator` dominates `node` in the CFG.
 *
 * Every node dominates itself.
 */
predicate dominates(BasicBlock dominator, BasicBlock node) {
  // Every node dominates itself
  dominator = node
  or
  // Entry dominates all reachable nodes
  dominator instanceof EntryBasicBlock and node.isReachable()
  or
  // A node is dominated by the nodes that dominate all its predecessors
  node != dominator and
  not node instanceof EntryBasicBlock and
  forall(BasicBlock pred | pred = node.getAPredecessor() | dominates(dominator, pred))
}

/**
 * Holds if `dominator` strictly dominates `node` in the CFG.
 *
 * Strict dominance excludes self-dominance.
 */
predicate strictlyDominates(BasicBlock dominator, BasicBlock node) {
  dominates(dominator, node) and dominator != node
}

/**
 * Holds if `idom` immediately dominates `node` in the CFG.
 *
 * The immediate dominator is the closest strict dominator.
 */
predicate immediatelyDominates(BasicBlock idom, BasicBlock node) {
  strictlyDominates(idom, node) and
  not exists(BasicBlock mid |
    strictlyDominates(idom, mid) and
    strictlyDominates(mid, node)
  )
}

/**
 * Gets the immediate dominator of `node`, if any.
 */
BasicBlock getImmediateDominator(BasicBlock node) {
  immediatelyDominates(result, node)
}

/**
 * Holds if `postDominator` post-dominates `node` in the CFG.
 *
 * Every node post-dominates itself.
 */
predicate postDominates(BasicBlock postDominator, BasicBlock node) {
  // Every node post-dominates itself
  postDominator = node
  or
  // Exit post-dominates all nodes that can reach it
  postDominator instanceof ExitBasicBlock and
  node.getASuccessor*() = postDominator
  or
  // A node is post-dominated by nodes that post-dominate all its successors
  node != postDominator and
  not node instanceof ExitBasicBlock and
  forall(BasicBlock succ | succ = node.getASuccessor() | postDominates(postDominator, succ))
}

/**
 * Holds if `postDominator` strictly post-dominates `node` in the CFG.
 */
predicate strictlyPostDominates(BasicBlock postDominator, BasicBlock node) {
  postDominates(postDominator, node) and postDominator != node
}

/**
 * Holds if `ipdom` immediately post-dominates `node` in the CFG.
 */
predicate immediatelyPostDominates(BasicBlock ipdom, BasicBlock node) {
  strictlyPostDominates(ipdom, node) and
  not exists(BasicBlock mid |
    strictlyPostDominates(ipdom, mid) and
    strictlyPostDominates(mid, node)
  )
}

/**
 * Gets the immediate post-dominator of `node`, if any.
 */
BasicBlock getImmediatePostDominator(BasicBlock node) {
  immediatelyPostDominates(result, node)
}

/**
 * The dominance frontier of a node N is the set of nodes M such that:
 * - N dominates a predecessor of M, but
 * - N does not strictly dominate M
 *
 * This is useful for SSA construction.
 */
predicate dominanceFrontier(BasicBlock node, BasicBlock frontier) {
  exists(BasicBlock pred |
    pred = frontier.getAPredecessor() and
    dominates(node, pred) and
    not strictlyDominates(node, frontier)
  )
}

/**
 * The iterated dominance frontier of a set of nodes.
 * Useful for placing phi functions in SSA.
 */
predicate iteratedDominanceFrontier(BasicBlock start, BasicBlock frontier) {
  dominanceFrontier(start, frontier)
  or
  exists(BasicBlock mid |
    iteratedDominanceFrontier(start, mid) and
    dominanceFrontier(mid, frontier)
  )
}

/**
 * A dominator tree node.
 */
class DominatorTreeNode extends BasicBlock {
  /** Gets the parent in the dominator tree (immediate dominator). */
  DominatorTreeNode getTreeParent() { immediatelyDominates(result, this) }

  /** Gets a child in the dominator tree. */
  DominatorTreeNode getATreeChild() { result.getTreeParent() = this }

  /** Gets the depth in the dominator tree (0 for entry). */
  int getTreeDepth() {
    this instanceof EntryBasicBlock and result = 0
    or
    result = this.getTreeParent().getTreeDepth() + 1
  }

  /** Gets an ancestor in the dominator tree. */
  DominatorTreeNode getAnTreeAncestor() {
    result = this
    or
    result = this.getTreeParent().getAnTreeAncestor()
  }

  /** Gets the lowest common ancestor with another node. */
  DominatorTreeNode getLCA(DominatorTreeNode other) {
    result = this.getAnTreeAncestor() and
    result = other.getAnTreeAncestor() and
    not exists(DominatorTreeNode deeper |
      deeper = this.getAnTreeAncestor() and
      deeper = other.getAnTreeAncestor() and
      deeper.getTreeDepth() > result.getTreeDepth()
    )
  }
}

/**
 * Holds if the edge from `pred` to `succ` is a back edge.
 *
 * A back edge goes from a node to one of its dominators,
 * indicating a loop in the CFG.
 */
predicate isBackEdge(BasicBlock pred, BasicBlock succ) {
  pred.getASuccessor() = succ and
  dominates(succ, pred)
}

/**
 * A natural loop in the CFG.
 *
 * A natural loop is identified by a back edge (tail -> header)
 * and consists of all nodes that can reach the tail without
 * going through the header.
 */
class NaturalLoop extends BasicBlock {
  BasicBlock tail;

  NaturalLoop() {
    isBackEdge(tail, this) and
    // This is the loop header
    dominates(this, tail)
  }

  /** Gets the loop header (entry point). */
  BasicBlock getHeader() { result = this }

  /** Gets the back edge source (loop tail). */
  BasicBlock getTail() { result = tail }

  /** Holds if `node` is in this loop. */
  predicate contains(BasicBlock node) {
    node = this
    or
    node = tail
    or
    exists(BasicBlock pred |
      this.contains(pred) and
      node = pred.getAPredecessor() and
      dominates(this, node)
    )
  }

  /** Gets a node in this loop. */
  BasicBlock getALoopNode() { this.contains(result) }

  /** Gets an exit edge from this loop. */
  BasicBlock getAnExitSuccessor() {
    exists(BasicBlock inside |
      this.contains(inside) and
      result = inside.getASuccessor() and
      not this.contains(result)
    )
  }

  /** Holds if this loop is nested inside `outer`. */
  predicate isNestedIn(NaturalLoop outer) {
    outer.contains(this) and
    outer != this
  }

  /** Gets the number of enclosing loops (0 for outermost loops). */
  int getNestingDepth() {
    result = count(NaturalLoop outer | this.isNestedIn(outer))
  }
}
