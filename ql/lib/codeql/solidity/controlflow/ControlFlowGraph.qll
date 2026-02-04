/**
 * Provides classes and predicates for working with the Control Flow Graph.
 *
 * The CFG represents the possible execution paths through a program.
 * Each node in the CFG corresponds to an AST node that represents
 * an executable unit (expression, statement, etc.).
 *
 * Example usage:
 * ```ql
 * import solidity
 * import codeql.solidity.controlflow.ControlFlowGraph
 *
 * from ControlFlowNode node
 * where node.getASuccessor().getASuccessor() = node  // 2-hop cycle
 * select node, "Part of a short cycle"
 * ```
 */

private import codeql.solidity.ast.internal.TreeSitter
private import internal.ControlFlowGraphImpl
private import internal.Completion
import BasicBlocks
import Dominance

/**
 * A node in the control flow graph.
 *
 * Each CFG node corresponds to an AST node that represents
 * an executable construct (expression, statement, etc.).
 */
class ControlFlowNode extends CfgNode {
  /** Gets an immediate successor of this node in the CFG. */
  ControlFlowNode getASuccessor() { successor(this, result) }

  /** Gets an immediate predecessor of this node in the CFG. */
  ControlFlowNode getAPredecessor() { result.getASuccessor() = this }

  /** Gets the basic block containing this node. */
  BasicBlock getBasicBlock() { result.getANode() = this }

  /** Holds if this node is reachable from the function entry. */
  predicate isReachable() { this.getBasicBlock().isReachable() }

  /** Gets the enclosing function. */
  ControlFlowNode getEnclosingFunction() {
    result = this.getBasicBlock().getEnclosingEntry()
  }

  /** Holds if this node is an entry point to a function. */
  predicate isEntryNode() { this instanceof EntryNode }

  /** Holds if this node is an exit point from a function. */
  predicate isExitNode() {
    exists(EntryNode entry | getAnExitNode(entry) = this)
  }

  /** Gets the AST node corresponding to this CFG node. */
  Solidity::AstNode getAstNode() { result = this }

  /** Gets the location of this CFG node. */
  override Location getLocation() { result = this.(Solidity::AstNode).getLocation() }

  /** Gets a textual representation of this CFG node. */
  override string toString() { result = this.(Solidity::AstNode).toString() }
}

/**
 * A function entry node in the CFG.
 */
class FunctionEntryNode extends ControlFlowNode, EntryNode {
  /** Gets the first executable node in this function. */
  ControlFlowNode getFirstNode() { result = first(this.getBody()) }

  /** Gets an exit node of this function. */
  ControlFlowNode getAnExitNode() { result = getAnExitNode(this) }

  /** Gets the name of this function (if applicable). */
  string getName() {
    result = this.(Solidity::FunctionDefinition).getName().(Solidity::AstNode).toString()
    or
    this instanceof Solidity::ConstructorDefinition and result = "constructor"
    or
    this instanceof Solidity::FallbackReceiveDefinition and result = "fallback/receive"
  }
}

/**
 * An expression node in the CFG.
 */
class ExpressionCfgNode extends ControlFlowNode {
  ExpressionCfgNode() { this instanceof Solidity::Expression }

  /** Gets the expression AST node. */
  Solidity::Expression getExpression() { result = this }
}

/**
 * A statement node in the CFG.
 */
class StatementCfgNode extends ControlFlowNode {
  StatementCfgNode() {
    this instanceof Solidity::ExpressionStatement or
    this instanceof Solidity::IfStatement or
    this instanceof Solidity::ForStatement or
    this instanceof Solidity::WhileStatement or
    this instanceof Solidity::DoWhileStatement or
    this instanceof Solidity::BlockStatement or
    this instanceof Solidity::ReturnStatement or
    this instanceof Solidity::BreakStatement or
    this instanceof Solidity::ContinueStatement or
    this instanceof Solidity::EmitStatement or
    this instanceof Solidity::RevertStatement or
    this instanceof Solidity::VariableDeclarationStatement or
    this instanceof Solidity::TryStatement or
    this instanceof Solidity::Unchecked or
    this instanceof Solidity::AssemblyStatement
  }
}

/**
 * A condition node in the CFG (used in if/while/for).
 */
class ConditionNode extends ExpressionCfgNode {
  ConditionNode() {
    exists(Solidity::IfStatement ifStmt | this = ifStmt.getCondition())
    or
    exists(Solidity::WhileStatement whileStmt | this = whileStmt.getCondition())
    or
    exists(Solidity::ForStatement forStmt | this = forStmt.getCondition())
    or
    exists(Solidity::DoWhileStatement doWhile | this = doWhile.getCondition())
  }

  /** Gets the true successor (when condition is true). */
  ControlFlowNode getTrueSuccessor() {
    exists(Solidity::IfStatement ifStmt |
      this = ifStmt.getCondition() and
      result = first(ifStmt.getBody(0))
    )
    or
    exists(Solidity::WhileStatement whileStmt |
      this = whileStmt.getCondition() and
      result = first(whileStmt.getBody())
    )
    or
    exists(Solidity::ForStatement forStmt |
      this = forStmt.getCondition() and
      result = first(forStmt.getBody())
    )
    or
    exists(Solidity::DoWhileStatement doWhile |
      this = doWhile.getCondition() and
      result = first(doWhile.getBody())
    )
  }

  /** Gets the false successor (when condition is false). */
  ControlFlowNode getFalseSuccessor() {
    result = this.getASuccessor() and
    result != this.getTrueSuccessor()
  }
}

/**
 * A loop header node in the CFG.
 */
class LoopNode extends StatementCfgNode {
  LoopNode() {
    this instanceof Solidity::ForStatement or
    this instanceof Solidity::WhileStatement or
    this instanceof Solidity::DoWhileStatement
  }

  /** Gets the condition of this loop. */
  ControlFlowNode getCondition() {
    result = this.(Solidity::ForStatement).getCondition()
    or
    result = this.(Solidity::WhileStatement).getCondition()
    or
    result = this.(Solidity::DoWhileStatement).getCondition()
  }

  /** Gets the body of this loop. */
  ControlFlowNode getBody() {
    result = first(this.(Solidity::ForStatement).getBody())
    or
    result = first(this.(Solidity::WhileStatement).getBody())
    or
    result = first(this.(Solidity::DoWhileStatement).getBody())
  }

  /** Holds if this is a for loop. */
  predicate isForLoop() { this instanceof Solidity::ForStatement }

  /** Holds if this is a while loop. */
  predicate isWhileLoop() { this instanceof Solidity::WhileStatement }

  /** Holds if this is a do-while loop. */
  predicate isDoWhileLoop() { this instanceof Solidity::DoWhileStatement }
}

/**
 * A call node in the CFG.
 */
class CallCfgNode extends ExpressionCfgNode {
  CallCfgNode() { this instanceof Solidity::CallExpression }

  /** Gets the call expression. */
  Solidity::CallExpression getCall() { result = this }

  /** Gets the callee expression. */
  ControlFlowNode getCallee() { result = this.(Solidity::CallExpression).getFunction() }

  /** Gets an argument to this call (arguments are stored as children). */
  ControlFlowNode getAnArgument() { result = this.(Solidity::CallExpression).getChild(_) }

  /** Gets the i-th argument to this call (arguments are stored as children). */
  ControlFlowNode getArgument(int i) { result = this.(Solidity::CallExpression).getChild(i) }
}

/**
 * A return node in the CFG.
 */
class ReturnNode extends StatementCfgNode {
  ReturnNode() { this instanceof Solidity::ReturnStatement }

  /** Gets the return value expression, if any. */
  ControlFlowNode getReturnValue() {
    result = this.(Solidity::ReturnStatement).getAFieldOrChild()
  }

  /** Holds if this return has a value. */
  predicate hasReturnValue() { exists(this.getReturnValue()) }
}

/**
 * A revert node in the CFG.
 */
class RevertNode extends StatementCfgNode {
  RevertNode() { this instanceof Solidity::RevertStatement }

  /** Gets the error expression, if any. */
  ControlFlowNode getError() {
    result = this.(Solidity::RevertStatement).getAFieldOrChild()
  }
}

// =============================================================================
// Yul/Assembly CFG Nodes
// =============================================================================

/**
 * An assembly statement node in the CFG.
 */
class AssemblyCfgNode extends StatementCfgNode {
  AssemblyCfgNode() { this instanceof Solidity::AssemblyStatement }

  /** Gets the inner Yul block. */
  YulBlockCfgNode getYulBlock() {
    result = this.(Solidity::AssemblyStatement).getChild(0)
  }
}

/**
 * A Yul block node in the CFG.
 */
class YulBlockCfgNode extends ControlFlowNode {
  YulBlockCfgNode() { this instanceof Solidity::YulBlock }

  /** Gets the i-th statement in this block. */
  ControlFlowNode getStatement(int i) {
    result = this.(Solidity::YulBlock).getChild(i)
  }

  /** Gets any statement in this block. */
  ControlFlowNode getAStatement() {
    result = this.(Solidity::YulBlock).getChild(_)
  }
}

/**
 * A Yul control flow node (if, for, switch).
 */
class YulControlFlowNode extends ControlFlowNode {
  YulControlFlowNode() {
    this instanceof Solidity::YulIfStatement or
    this instanceof Solidity::YulForStatement or
    this instanceof Solidity::YulSwitchStatement
  }
}

/**
 * A Yul if statement node in the CFG.
 */
class YulIfCfgNode extends YulControlFlowNode {
  YulIfCfgNode() { this instanceof Solidity::YulIfStatement }

  /** Gets the condition. */
  ControlFlowNode getCondition() {
    result = this.(Solidity::YulIfStatement).getChild(0)
  }

  /** Gets the body (executed when condition is non-zero). */
  ControlFlowNode getBody() {
    result = first(this.(Solidity::YulIfStatement).getChild(1))
  }
}

/**
 * A Yul for statement node in the CFG.
 */
class YulForCfgNode extends YulControlFlowNode {
  YulForCfgNode() { this instanceof Solidity::YulForStatement }

  /** Gets the initialization block. */
  ControlFlowNode getInit() {
    result = first(this.(Solidity::YulForStatement).getChild(0))
  }

  /** Gets the condition. */
  ControlFlowNode getCondition() {
    result = this.(Solidity::YulForStatement).getChild(1)
  }

  /** Gets the update block. */
  ControlFlowNode getUpdate() {
    result = first(this.(Solidity::YulForStatement).getChild(2))
  }

  /** Gets the body. */
  ControlFlowNode getBody() {
    result = first(this.(Solidity::YulForStatement).getChild(3))
  }
}

/**
 * A Yul switch statement node in the CFG.
 */
class YulSwitchCfgNode extends YulControlFlowNode {
  YulSwitchCfgNode() { this instanceof Solidity::YulSwitchStatement }

  /** Gets the switch expression. */
  ControlFlowNode getExpression() {
    result = this.(Solidity::YulSwitchStatement).getChild(0)
  }

  /** Gets the i-th case (0 is expression, 1+ are cases). */
  ControlFlowNode getCase(int i) {
    i > 0 and
    result = this.(Solidity::YulSwitchStatement).getChild(i)
  }
}

/**
 * A Yul function call node in the CFG.
 */
class YulCallCfgNode extends ControlFlowNode {
  YulCallCfgNode() { this instanceof Solidity::YulFunctionCall }

  /** Gets the function being called. */
  ControlFlowNode getFunction() {
    result = this.(Solidity::YulFunctionCall).getFunction()
  }

  /** Gets an argument to this call. */
  ControlFlowNode getAnArgument() {
    result = this.(Solidity::YulFunctionCall).getChild(_)
  }
}

/**
 * A Yul jump statement node (break, continue, leave).
 */
class YulJumpNode extends ControlFlowNode {
  YulJumpNode() {
    this instanceof Solidity::YulBreak or
    this instanceof Solidity::YulContinue or
    this instanceof Solidity::YulLeave
  }

  /** Holds if this is a break. */
  predicate isBreak() { this instanceof Solidity::YulBreak }

  /** Holds if this is a continue. */
  predicate isContinue() { this instanceof Solidity::YulContinue }

  /** Holds if this is a leave (exits Yul function). */
  predicate isLeave() { this instanceof Solidity::YulLeave }
}

/**
 * Holds if there is a path from `source` to `sink` in the CFG.
 */
predicate hasPath(ControlFlowNode source, ControlFlowNode sink) {
  source = sink
  or
  hasPath(source.getASuccessor(), sink)
}

/**
 * Holds if `node` is reachable from the function entry.
 */
predicate isReachableFromEntry(ControlFlowNode node) {
  node instanceof FunctionEntryNode
  or
  isReachableFromEntry(node.getAPredecessor())
}
