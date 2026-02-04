/**
 * Provides analysis of Solidity modifiers.
 *
 * This module handles:
 * - Modifier invocation resolution
 * - Data flow through modifiers
 * - Modifier validation patterns
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Contract
private import codeql.solidity.ast.Function
private import codeql.solidity.callgraph.InheritanceGraph

/**
 * Gets the modifier name from a modifier definition.
 */
private string getModifierName(Solidity::ModifierDefinition mod) {
  result = mod.getName().(Solidity::AstNode).getValue()
}

/**
 * Module for modifier analysis.
 */
module ModifierAnalysis {
  /**
   * Resolves a modifier invocation to its definition.
   *
   * Handles both local modifiers and inherited modifiers.
   */
  predicate resolveModifier(
    Solidity::ModifierInvocation inv,
    Solidity::ModifierDefinition mod
  ) {
    exists(Solidity::Identifier modRef, Solidity::ContractDeclaration contract, string modName |
      // Get the modifier reference from the invocation
      modRef = inv.getChild(0).getAChild*() and
      modName = modRef.getValue() and
      // The function with this modifier is in a contract
      inv.getParent+() = contract and
      // Find modifier definition
      getModifierName(mod) = modName and
      (
        // Same contract
        mod.getParent+() = contract
        or
        // Inherited modifier
        mod.getParent+() = InheritanceGraph::getInheritanceChain(contract)
      )
    )
  }

  /**
   * Gets the definition of a modifier applied to a function.
   */
  Solidity::ModifierDefinition getModifierDefinition(
    Solidity::FunctionDefinition func,
    Solidity::ModifierInvocation inv
  ) {
    inv.getParent() = func and
    resolveModifier(inv, result)
  }

  /**
   * Gets all modifiers applied to a function.
   */
  Solidity::ModifierInvocation getAppliedModifier(Solidity::FunctionDefinition func) {
    result.getParent() = func
  }

  /**
   * Gets the number of modifiers applied to a function.
   */
  int getModifierCount(Solidity::FunctionDefinition func) {
    result = count(getAppliedModifier(func))
  }

  /**
   * Holds if `func` has any modifiers applied.
   */
  predicate hasModifiers(Solidity::FunctionDefinition func) {
    exists(getAppliedModifier(func))
  }

  /**
   * Holds if `mod` contains a require statement.
   */
  predicate hasRequire(Solidity::ModifierDefinition mod) {
    exists(Solidity::CallExpression call, Solidity::Identifier reqId |
      call.getParent+() = mod and
      reqId = call.getFunction().getAChild*() and
      reqId.getValue() = "require"
    )
  }

  /**
   * Holds if `mod` contains a revert statement.
   */
  predicate hasRevert(Solidity::ModifierDefinition mod) {
    exists(Solidity::RevertStatement rev |
      rev.getParent+() = mod
    )
    or
    exists(Solidity::CallExpression call, Solidity::Identifier revId |
      call.getParent+() = mod and
      revId = call.getFunction().getAChild*() and
      revId.getValue() = "revert"
    )
  }

  /**
   * Holds if `mod` performs input validation (has require or revert).
   */
  predicate performsValidation(Solidity::ModifierDefinition mod) {
    hasRequire(mod) or hasRevert(mod)
  }

  /**
   * Holds if `mod` validates a specific parameter by index.
   */
  predicate validatesParameter(Solidity::ModifierDefinition mod, int paramIndex) {
    exists(
      Solidity::CallExpression req,
      Solidity::Identifier reqId,
      Solidity::Parameter param,
      Solidity::Identifier paramRef
    |
      // Find require call in modifier
      req.getParent+() = mod and
      reqId = req.getFunction().getAChild*() and
      reqId.getValue() = "require" and
      // Parameter at given index
      param = mod.getChild(paramIndex) and
      param instanceof Solidity::Parameter and
      // Parameter is referenced in require
      paramRef.getParent+() = req and
      paramRef.getValue() = param.getName().(Solidity::AstNode).getValue()
    )
  }

  /**
   * Holds if `mod` contains a comparison check (>=, <=, >, <, ==, !=).
   */
  predicate hasComparisonCheck(Solidity::ModifierDefinition mod) {
    exists(Solidity::BinaryExpression check |
      check.getParent+() = mod and
      check.getOperator().(Solidity::AstNode).getValue() in [">=", "<=", ">", "<", "==", "!="]
    )
  }

  /**
   * Holds if `mod` validates against a max value (overflow check pattern).
   */
  predicate hasOverflowCheck(Solidity::ModifierDefinition mod) {
    exists(Solidity::CallExpression req, Solidity::Identifier reqId |
      req.getParent+() = mod and
      reqId = req.getFunction().getAChild*() and
      reqId.getValue() = "require" and
      (
        // Check for max comparison
        exists(Solidity::Identifier maxId |
          maxId.getParent+() = req and
          maxId.getValue() = "max"
        )
        or
        // Check for type(uint).max pattern
        exists(Solidity::MemberExpression typeMax |
          typeMax.getParent+() = req and
          typeMax.getProperty().(Solidity::AstNode).getValue() = "max"
        )
        or
        // Has comparison operators
        exists(Solidity::BinaryExpression check |
          check.getParent+() = req and
          check.getOperator().(Solidity::AstNode).getValue() in ["<", "<=", ">", ">="]
        )
      )
    )
  }

  /**
   * Holds if `mod` checks msg.sender (access control pattern).
   */
  predicate checksMessageSender(Solidity::ModifierDefinition mod) {
    exists(Solidity::MemberExpression member |
      member.getParent+() = mod and
      member.getObject().(Solidity::Identifier).getValue() = "msg" and
      member.getProperty().(Solidity::AstNode).getValue() = "sender"
    )
  }

  /**
   * Holds if `mod` is an access control modifier (checks sender).
   */
  predicate isAccessControlModifier(Solidity::ModifierDefinition mod) {
    checksMessageSender(mod) and performsValidation(mod)
  }

  /**
   * Holds if `mod` is a reentrancy guard (contains nonReentrant pattern).
   */
  predicate isReentrancyGuard(Solidity::ModifierDefinition mod) {
    getModifierName(mod).toLowerCase().matches("%reentr%")
    or
    // Check for locked pattern
    exists(Solidity::Identifier id |
      id.getParent+() = mod and
      id.getValue().toLowerCase() in ["_locked", "locked", "_status", "status"]
    )
  }

  /**
   * Holds if `func` is protected by a reentrancy guard.
   */
  predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
    exists(Solidity::ModifierInvocation inv, Solidity::ModifierDefinition mod |
      inv.getParent() = func and
      resolveModifier(inv, mod) and
      isReentrancyGuard(mod)
    )
  }

  /**
   * Holds if `func` has access control via modifier.
   */
  predicate hasAccessControlModifier(Solidity::FunctionDefinition func) {
    exists(Solidity::ModifierInvocation inv, Solidity::ModifierDefinition mod |
      inv.getParent() = func and
      resolveModifier(inv, mod) and
      isAccessControlModifier(mod)
    )
  }

  /**
   * Holds if `mod` contains the placeholder (_) for function body execution.
   *
   * The placeholder is represented as an identifier with value "_" in the AST.
   */
  predicate hasPlaceholder(Solidity::ModifierDefinition mod) {
    exists(Solidity::Identifier p |
      p.getParent+() = mod and
      p.getValue() = "_"
    )
  }

  /**
   * Holds if `mod` performs external calls (potential reentrancy risk).
   */
  predicate makesExternalCalls(Solidity::ModifierDefinition mod) {
    exists(Solidity::CallExpression call, Solidity::MemberExpression member |
      call.getParent+() = mod and
      member = call.getFunction().getAChild*() and
      member.getProperty().(Solidity::AstNode).getValue() in ["call", "delegatecall", "staticcall", "transfer", "send"]
    )
  }

  /**
   * Holds if `mod` modifies state before the placeholder.
   */
  predicate modifiesStateBeforePlaceholder(Solidity::ModifierDefinition mod) {
    exists(
      Solidity::AssignmentExpression assign,
      Solidity::Identifier placeholder
    |
      assign.getParent+() = mod and
      placeholder.getParent+() = mod and
      placeholder.getValue() = "_" and
      assign.getLocation().getStartLine() < placeholder.getLocation().getStartLine()
    )
  }

  /**
   * Gets the argument passed to a modifier invocation at index `i`.
   */
  Solidity::AstNode getModifierArgument(Solidity::ModifierInvocation inv, int i) {
    // Arguments start at child 1 (child 0 is the modifier name)
    result = inv.getChild(i + 1) and
    i >= 0
  }

  /**
   * Gets the number of arguments in a modifier invocation.
   */
  int getModifierArgumentCount(Solidity::ModifierInvocation inv) {
    result = count(int i | i >= 0 and exists(inv.getChild(i + 1))) - 1
    or
    // If only the name, no arguments
    not exists(inv.getChild(1)) and result = 0
  }

  /**
   * A modifier definition that performs overflow/underflow checking.
   */
  class OverflowCheckModifier extends Solidity::ModifierDefinition {
    OverflowCheckModifier() {
      hasOverflowCheck(this)
    }

    /** Gets the modifier name. */
    string getOverflowCheckModifierName() {
      result = getModifierName(this)
    }
  }

  /**
   * A modifier definition that provides access control.
   */
  class AccessControlModifier extends Solidity::ModifierDefinition {
    AccessControlModifier() {
      isAccessControlModifier(this)
    }

    /** Gets the modifier name. */
    string getAccessControlModifierName() {
      result = getModifierName(this)
    }
  }

  /**
   * A modifier definition that provides reentrancy protection.
   */
  class ReentrancyGuardModifier extends Solidity::ModifierDefinition {
    ReentrancyGuardModifier() {
      isReentrancyGuard(this)
    }

    /** Gets the modifier name. */
    string getReentrancyGuardModifierName() {
      result = getModifierName(this)
    }
  }
}
