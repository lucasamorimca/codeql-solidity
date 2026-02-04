/**
 * Expression nodes in Solidity AST.
 *
 * This module provides classes for all expression types in Solidity.
 */

private import codeql.solidity.ast.internal.TreeSitter

/**
 * An expression in Solidity source code.
 */
class Expr extends Solidity::AstNode {
  Expr() {
    this instanceof Solidity::BinaryExpression or
    this instanceof Solidity::UnaryExpression or
    this instanceof Solidity::CallExpression or
    this instanceof Solidity::MemberExpression or
    this instanceof Solidity::Identifier or
    this instanceof Solidity::NumberLiteral or
    this instanceof Solidity::StringLiteral or
    this instanceof Solidity::BooleanLiteral or
    this instanceof Solidity::AssignmentExpression or
    this instanceof Solidity::TernaryExpression or
    this instanceof Solidity::ArrayAccess or
    this instanceof Solidity::TupleExpression or
    this instanceof Solidity::NewExpression or
    this instanceof Solidity::TypeCastExpression or
    this instanceof Solidity::PayableConversionExpression
  }
}

/**
 * A binary expression (e.g., `a + b`, `x && y`).
 */
class BinaryExpr extends Solidity::BinaryExpression {
  /** Gets the left operand. */
  Solidity::AstNode getLeftOperand() { result = super.getLeft() }

  /** Gets the right operand. */
  Solidity::AstNode getRightOperand() { result = super.getRight() }

  /** Gets the operator as a string. */
  string getOperatorString() {
    exists(Solidity::AstNode op | op = super.getOperator() |
      solidity_tokeninfo(op, _, result)
    )
  }
}

/**
 * A unary expression (e.g., `!x`, `++i`).
 */
class UnaryExpr extends Solidity::UnaryExpression {
  /** Gets the operand. */
  Solidity::AstNode getOperand() { result = super.getArgument() }
}

/**
 * A function call expression.
 */
class CallExpr extends Solidity::CallExpression {
  /** Gets the callee (function being called). */
  Solidity::AstNode getCallee() { result = super.getFunction() }

  /** Gets an argument to the call. */
  Solidity::AstNode getAnArgument() { result = this.getAChild() }

  /** Gets the i-th argument (0-indexed). */
  Solidity::AstNode getArgumentAt(int i) { result = this.getChild(i) }

  /** Gets the number of arguments. */
  int getNumArguments() { result = count(this.getAChild()) }
}

/**
 * A member access expression (e.g., `obj.member`).
 */
class MemberExpr extends Solidity::MemberExpression {
  /** Gets the object being accessed. */
  Solidity::AstNode getObjectExpr() { result = super.getObject() }

  /** Gets the property/member name. */
  Solidity::AstNode getPropertyNode() { result = super.getProperty() }
}

/**
 * An identifier (variable reference).
 */
class Identifier extends Solidity::Identifier {
  /** Gets the name of this identifier. */
  string getIdentifierName() {
    solidity_tokeninfo(this, _, result)
  }
}

/**
 * A numeric literal.
 */
class NumberLiteral extends Solidity::NumberLiteral {
  /** Gets the literal value as a string. */
  string getLiteralValue() {
    solidity_tokeninfo(this, _, result)
  }
}

/**
 * A string literal.
 */
class StringLiteral extends Solidity::StringLiteral {
  /** Gets the literal value. */
  string getLiteralValue() {
    solidity_tokeninfo(this, _, result)
  }
}

/**
 * A boolean literal (`true` or `false`).
 */
class BooleanLiteral extends Solidity::BooleanLiteral {
  /** Gets the boolean value. */
  boolean getBoolValue() {
    solidity_tokeninfo(this, _, "true") and result = true
    or
    solidity_tokeninfo(this, _, "false") and result = false
  }
}

/**
 * An assignment expression.
 */
class AssignmentExpr extends Solidity::AssignmentExpression {
  /** Gets the left-hand side (target). */
  Solidity::AstNode getTarget() { result = super.getLeft() }

  /** Gets the right-hand side (value). */
  Solidity::AstNode getRhsValue() { result = super.getRight() }
}
