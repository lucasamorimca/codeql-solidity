/**
 * Statement nodes in Solidity AST.
 *
 * This module provides classes for all statement types in Solidity.
 */

private import codeql.solidity.ast.internal.TreeSitter

/**
 * A statement in Solidity source code.
 */
class Stmt extends Solidity::AstNode {
  Stmt() {
    this instanceof Solidity::IfStatement or
    this instanceof Solidity::ForStatement or
    this instanceof Solidity::WhileStatement or
    this instanceof Solidity::DoWhileStatement or
    this instanceof Solidity::BlockStatement or
    this instanceof Solidity::ReturnStatement or
    this instanceof Solidity::EmitStatement or
    this instanceof Solidity::RevertStatement or
    this instanceof Solidity::VariableDeclarationStatement or
    this instanceof Solidity::ExpressionStatement or
    this instanceof Solidity::TryStatement or
    this instanceof Solidity::Unchecked or
    this instanceof Solidity::AssemblyStatement
  }
}

/**
 * An if statement.
 */
class IfStmt extends Solidity::IfStatement {
  /** Gets the condition expression. */
  Solidity::AstNode getConditionExpr() { result = super.getCondition() }

  /** Gets the body (then branch). */
  Solidity::AstNode getThenBranch() { result = super.getBody(0) }

  /** Gets the else branch, if any. */
  Solidity::AstNode getElseBranch() { result = super.getElse() }

  /** Holds if this if statement has an else branch. */
  predicate hasElse() { exists(this.getElseBranch()) }
}

/**
 * A for loop statement.
 */
class ForStmt extends Solidity::ForStatement {
  /** Gets the initialization part. */
  Solidity::AstNode getInitExpr() { result = super.getInitial() }

  /** Gets the loop body. */
  Solidity::AstNode getBodyStmt() { result = super.getBody() }
}

/**
 * A while loop statement.
 */
class WhileStmt extends Solidity::WhileStatement {
  /** Gets the loop body. */
  Solidity::AstNode getBodyStmt() { result = super.getBody() }
}

/**
 * A do-while loop statement.
 */
class DoWhileStmt extends Solidity::DoWhileStatement {
  /** Gets the loop body. */
  Solidity::AstNode getBodyStmt() { result = super.getBody() }
}

/**
 * A block statement (code enclosed in braces).
 */
class BlockStmt extends Solidity::BlockStatement {
  /** Gets a statement in this block. */
  Solidity::AstNode getAStatement() { result = this.getAChild() }

  /** Gets the i-th statement in this block (0-indexed). */
  Solidity::AstNode getStatement(int i) { result = this.getChild(i) }
}

/**
 * A return statement.
 */
class ReturnStmt extends Solidity::ReturnStatement {
  /** Gets the return value expression, if any. */
  Solidity::AstNode getReturnExpr() { result = this.getAChild() }

  /** Holds if this return statement returns a value. */
  predicate hasReturnValue() { exists(this.getReturnExpr()) }
}

/**
 * An emit statement (for emitting events).
 */
class EmitStmt extends Solidity::EmitStatement {
  /** Gets the event call. */
  Solidity::AstNode getEventCall() { result = this.getAChild() }
}

/**
 * A revert statement.
 */
class RevertStmt extends Solidity::RevertStatement {
  /** Gets the error call or message. */
  Solidity::AstNode getErrorExpr() { result = this.getAChild() }
}

/**
 * A variable declaration statement.
 */
class VarDeclStmt extends Solidity::VariableDeclarationStatement {
  /** Gets the declared variable. */
  Solidity::AstNode getVariable() { result = this.getAChild() }

  /** Gets the initializer expression, if any. */
  Solidity::AstNode getInitializer() { result = super.getFieldValue() }

  /** Holds if this declaration has an initializer. */
  predicate hasInitializer() { exists(this.getInitializer()) }
}

/**
 * An expression statement.
 */
class ExprStmt extends Solidity::ExpressionStatement {
  /** Gets the expression. */
  Solidity::AstNode getExpression() { result = this.getAChild() }
}

/**
 * A try statement.
 */
class TryStmt extends Solidity::TryStatement {
  /** Gets the external call being tried. */
  Solidity::AstNode getAttemptExpr() { result = super.getAttempt() }

  /** Gets the body executed on success. */
  Solidity::AstNode getSuccessBody() { result = super.getBody() }

  /** Gets a catch clause. */
  Solidity::AstNode getACatchClause() {
    result = this.getAChild() and result instanceof Solidity::CatchClause
  }
}

/**
 * An unchecked block (arithmetic without overflow checking).
 */
class UncheckedBlock extends Solidity::Unchecked {
  /** Gets the body of this unchecked block. */
  Solidity::AstNode getBlockBody() { result = this.getAChild() }
}

/**
 * An assembly/Yul statement.
 */
class AssemblyStmt extends Solidity::AssemblyStatement {
  /** Gets the assembly body. */
  Solidity::AstNode getAssemblyBody() { result = this.getAChild() }
}
