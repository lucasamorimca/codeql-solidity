# Control Flow Analysis

This guide covers control flow graph (CFG) analysis, basic blocks, and dominance for advanced query patterns.

## CFG Overview

The CFG represents execution paths through code. Each node is an AST element with successor/predecessor edges.

**Key modules:**
- `codeql.solidity.controlflow.ControlFlowGraph` - CFG nodes
- `codeql.solidity.controlflow.BasicBlocks` - Block analysis
- `codeql.solidity.controlflow.Dominance` - Dominance relations

## ControlFlowNode

Wraps AST nodes as CFG nodes with navigation methods.

```ql
import codeql.solidity.controlflow.ControlFlowGraph

from ControlFlowNode node
where node.isEntryNode()
select node, "Function entry point"
```

**Key methods:**

| Method | Description |
|--------|-------------|
| `getASuccessor()` | Next node(s) in CFG |
| `getAPredecessor()` | Previous node(s) in CFG |
| `getBasicBlock()` | Containing basic block |
| `isReachable()` | Reachable from entry |
| `isEntryNode()` | Is function entry |
| `isExitNode()` | Is function exit |
| `getEnclosingFunction()` | Containing function |

### CFG Navigation

```ql
/** Gets nodes reachable from function entry. */
ControlFlowNode getReachableNode(Solidity::FunctionDefinition func) {
  exists(ControlFlowNode entry |
    entry.isEntryNode() and
    entry.getEnclosingFunction() = func and
    result = entry.getASuccessor*()
  )
}

/** Holds if node2 follows node1 in CFG. */
predicate follows(ControlFlowNode node1, ControlFlowNode node2) {
  node2 = node1.getASuccessor+()
}
```

### Finding Unreachable Code

```ql
/**
 * @name Unreachable code
 * @description Code that cannot be executed
 * @kind problem
 * @id solidity/unreachable-code
 */

import codeql.solidity.controlflow.ControlFlowGraph

from ControlFlowNode node
where
  not node.isReachable() and
  exists(node.getEnclosingFunction())
select node, "Unreachable code"
```

### Finding Code After Return

```ql
from
  Solidity::ReturnStatement ret,
  ControlFlowNode retNode,
  ControlFlowNode afterRet
where
  retNode = ret and
  afterRet = retNode.getASuccessor() and
  not afterRet.isExitNode()
select afterRet, "Code after return statement"
```

## Basic Blocks

A basic block is a maximal sequence of CFG nodes with single entry/exit.

```ql
import codeql.solidity.controlflow.BasicBlocks

from BasicBlock bb
select bb, bb.getANode()
```

**Block boundaries occur at:**
- Function entry
- Multiple predecessors (join)
- Predecessor has multiple successors (branch)

**Key methods:**

| Method | Description |
|--------|-------------|
| `getASuccessor()` | Successor block(s) |
| `getAPredecessor()` | Predecessor block(s) |
| `getNode(int)` | Node at index |
| `getANode()` | Any node in block |
| `getFirstNode()` | First node |
| `getLastNode()` | Last node |
| `isReachable()` | Reachable from entry |

### Block Navigation

```ql
/** Gets successor blocks. */
BasicBlock getSuccessorBlock(BasicBlock bb) {
  result = bb.getASuccessor()
}

/** Holds if block is a join point (multiple predecessors). */
predicate isJoinBlock(BasicBlock bb) {
  count(bb.getAPredecessor()) > 1
}

/** Holds if block is a branch point (multiple successors). */
predicate isBranchBlock(BasicBlock bb) {
  count(bb.getASuccessor()) > 1
}
```

### Finding Loop Headers

```ql
/** Holds if block is a loop header (back edge target). */
predicate isLoopHeader(BasicBlock bb) {
  exists(BasicBlock pred |
    pred = bb.getAPredecessor() and
    bb.getASuccessor+() = pred
  )
}

from BasicBlock bb
where isLoopHeader(bb)
select bb, "Loop header"
```

### Counting Paths

```ql
/** Gets number of paths through block. */
int pathCount(BasicBlock bb) {
  result = count(BasicBlock succ | succ = bb.getASuccessor())
}
```

## Dominance Analysis

Block A dominates block B if every path from entry to B goes through A.

```ql
import codeql.solidity.controlflow.Dominance

/** Holds if `dom` dominates `bb`. */
predicate dominates(BasicBlock dom, BasicBlock bb) {
  Dominance::dominates(dom, bb)
}
```

### Finding Dominance Frontier

The dominance frontier of A is the set of blocks where A's dominance ends.

```ql
/** Gets dominance frontier of block. */
BasicBlock getDominanceFrontier(BasicBlock bb) {
  exists(BasicBlock succ |
    succ = bb.getASuccessor() and
    not Dominance::strictlyDominates(bb, succ)
  |
    result = succ
  )
}
```

## CFG Patterns

### Detecting Infinite Loops

```ql
from BasicBlock bb
where
  isLoopHeader(bb) and
  not exists(BasicBlock exit |
    bb.getASuccessor+() = exit and
    exit.getASuccessor() != bb.getASuccessor*()
  )
select bb, "Potential infinite loop"
```

### Finding All Paths Between Nodes

```ql
/** Holds if there's a path from start to end. */
predicate hasPath(ControlFlowNode start, ControlFlowNode end) {
  end = start.getASuccessor*()
}

/** Holds if all paths from start reach end. */
predicate allPathsReach(ControlFlowNode start, ControlFlowNode end) {
  hasPath(start, end) and
  forall(ControlFlowNode exit |
    exit.isExitNode() and hasPath(start, exit)
  |
    hasPath(end, exit)
  )
}
```

### Branch Analysis

```ql
from Solidity::IfStatement ifStmt, ControlFlowNode condition, ControlFlowNode trueBranch, ControlFlowNode falseBranch
where
  condition = ifStmt.getCondition() and
  trueBranch = condition.getASuccessor() and
  falseBranch = condition.getASuccessor() and
  trueBranch != falseBranch
select ifStmt, "If statement with true and false branches"
```

## Performance Tips

1. **Use basic blocks** for coarse-grained analysis
2. **Limit transitive closure** depth when possible
3. **Add early filters** before CFG navigation
4. **Cache reachability** in predicates

```ql
// Good: Filter first, then navigate
from ControlFlowNode node
where
  node.getEnclosingFunction().getName().toString() = "withdraw" and
  node.getASuccessor+().isExitNode()
select node

// Bad: Navigate first, then filter
from ControlFlowNode node
where
  node.getASuccessor+().isExitNode() and
  node.getEnclosingFunction().getName().toString() = "withdraw"
select node
```

## Next Steps

- [Data Flow](04-data-flow.md) - Taint tracking and SSA
- [Call Graph](05-call-graph.md) - Function resolution
- [Security Queries](06-writing-security-queries.md) - Using CFG for security
