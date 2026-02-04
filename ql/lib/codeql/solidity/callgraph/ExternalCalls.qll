/**
 * Provides detection and analysis of external calls in Solidity.
 *
 * External calls are calls that cross contract boundaries, including:
 * - Low-level calls (call, delegatecall, staticcall)
 * - Interface/contract method calls
 * - this.function() calls
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Contract
private import codeql.solidity.ast.Function

/**
 * Module for external call detection and analysis.
 */
module ExternalCalls {
  /**
   * Holds if `call` is a low-level call (call, delegatecall, staticcall).
   */
  predicate isLowLevelCall(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getProperty().(Solidity::AstNode).getValue() in ["call", "delegatecall", "staticcall"]
    )
  }

  /**
   * Holds if `call` is a call() low-level operation.
   */
  predicate isCall(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getProperty().(Solidity::AstNode).getValue() = "call"
    )
  }

  /**
   * Holds if `call` is a delegatecall() operation.
   */
  predicate isDelegateCall(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getProperty().(Solidity::AstNode).getValue() = "delegatecall"
    )
  }

  /**
   * Holds if `call` is a staticcall() operation.
   */
  predicate isStaticCall(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getProperty().(Solidity::AstNode).getValue() = "staticcall"
    )
  }

  /**
   * Holds if `call` is a this.function() call (external self-call).
   */
  predicate isThisCall(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getObject().(Solidity::Identifier).getValue() = "this"
    )
  }

  /**
   * Holds if `id` refers to a state variable of contract/interface type.
   */
  predicate isContractTypedStateVariable(Solidity::Identifier id) {
    exists(
      Solidity::StateVariableDeclaration stateVar,
      Solidity::ContractDeclaration contract
    |
      stateVar.getParent+() = contract and
      id.getParent+() = contract and
      stateVar.getName().(Solidity::AstNode).getValue() = id.getValue() and
      hasContractType(stateVar)
    )
  }

  /**
   * Holds if `id` refers to a parameter of contract/interface type.
   */
  predicate isContractTypedParameter(Solidity::Identifier id) {
    exists(Solidity::Parameter param, Solidity::FunctionDefinition func |
      param.getParent() = func and
      id.getParent+() = func and
      param.getName().(Solidity::AstNode).getValue() = id.getValue() and
      hasContractType(param)
    )
  }

  /**
   * Holds if `id` refers to a local variable of contract/interface type.
   */
  predicate isContractTypedLocalVariable(Solidity::Identifier id) {
    exists(
      Solidity::VariableDeclarationStatement decl,
      Solidity::FunctionDefinition func,
      Solidity::Identifier declName
    |
      decl.getParent+() = func and
      id.getParent+() = func and
      // Get name from the child identifier of the declaration
      declName.getParent+() = decl and
      declName.getValue() = id.getValue() and
      hasContractTypeDecl(decl)
    )
  }

  /**
   * Holds if `node` has a contract or interface type.
   */
  predicate hasContractType(Solidity::AstNode node) {
    exists(Solidity::Identifier typeId |
      typeId = node.getAFieldOrChild().getAChild*() and
      (
        // Type name matches a contract name
        exists(Solidity::ContractDeclaration c |
          c.getName().(Solidity::AstNode).getValue() = typeId.getValue()
        )
        or
        // Type name matches an interface name
        exists(Solidity::InterfaceDeclaration i |
          i.getName().(Solidity::AstNode).getValue() = typeId.getValue()
        )
      )
    )
  }

  /**
   * Holds if `decl` has a contract or interface type (for local variable declarations).
   */
  predicate hasContractTypeDecl(Solidity::VariableDeclarationStatement decl) {
    exists(Solidity::Identifier typeId |
      typeId = decl.getAFieldOrChild().getAChild*() and
      (
        exists(Solidity::ContractDeclaration c |
          c.getName().(Solidity::AstNode).getValue() = typeId.getValue()
        )
        or
        exists(Solidity::InterfaceDeclaration i |
          i.getName().(Solidity::AstNode).getValue() = typeId.getValue()
        )
      )
    )
  }

  /**
   * Holds if `id` refers to an external contract reference (state var, param, or local).
   */
  predicate isExternalReference(Solidity::Identifier id) {
    isContractTypedStateVariable(id) or
    isContractTypedParameter(id) or
    isContractTypedLocalVariable(id)
  }

  /**
   * Holds if `call` is a call through an external contract reference.
   *
   * Example: `token.transfer(...)` where `token` is of IERC20 type.
   */
  predicate isContractReferenceCall(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member, Solidity::Identifier base |
      member = call.getFunction().getAChild*() and
      base = member.getObject().getAChild*() and
      isExternalReference(base) and
      // Not a special call like call/delegatecall
      not member.getProperty().(Solidity::AstNode).getValue() in [
        "call", "delegatecall", "staticcall", "transfer", "send"
      ]
    )
  }

  /**
   * Holds if `call` is an ether transfer (transfer or send).
   */
  predicate isEtherTransfer(Solidity::CallExpression call) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getProperty().(Solidity::AstNode).getValue() in ["transfer", "send"]
    )
  }

  /**
   * A call expression that crosses contract boundaries.
   */
  class ExternalCall extends Solidity::CallExpression {
    ExternalCall() {
      isLowLevelCall(this) or
      isThisCall(this) or
      isContractReferenceCall(this) or
      isEtherTransfer(this)
    }

    /**
     * Holds if this is a low-level call (call, delegatecall, staticcall).
     */
    predicate isLowLevel() {
      isLowLevelCall(this)
    }

    /**
     * Holds if this is a delegatecall (highest risk for storage manipulation).
     */
    predicate isDelegateCall() {
      isDelegateCall(this)
    }

    /**
     * Holds if this is a call through an external reference.
     */
    predicate isThroughReference() {
      isContractReferenceCall(this)
    }

    /**
     * Holds if this is a this.func() external self-call.
     */
    predicate isSelfCall() {
      isThisCall(this)
    }

    /**
     * Gets the target address expression for low-level calls.
     */
    Solidity::AstNode getTargetAddress() {
      exists(Solidity::MemberExpression member |
        member = this.getFunction().getAChild*() and
        result = member.getObject()
      )
    }

    /**
     * Gets the data argument for low-level calls.
     */
    Solidity::AstNode getCallData() {
      isLowLevelCall(this) and
      result = this.getChild(0)
    }

    /**
     * Gets the value sent with this call (if payable call).
     */
    Solidity::AstNode getValueSent() {
      // For call{value: x}(data), look for value in the call structure
      // Value is typically passed as a named argument or in braces
      exists(Solidity::Identifier valueId |
        valueId.getParent+() = this and
        valueId.getValue() = "value" and
        result = valueId.getParent().getAChild()
      )
    }

    /**
     * Gets the enclosing function of this external call.
     */
    Solidity::FunctionDefinition getEnclosingFunction() {
      this.getParent+() = result
    }

    /**
     * Gets the enclosing contract of this external call.
     */
    Solidity::ContractDeclaration getEnclosingContract() {
      this.getParent+() = result
    }
  }

  /**
   * Gets all external calls in a function.
   */
  ExternalCall getExternalCallsInFunction(Solidity::FunctionDefinition func) {
    result.getParent+() = func
  }

  /**
   * Gets all external calls in a contract.
   */
  ExternalCall getExternalCallsInContract(Solidity::ContractDeclaration contract) {
    result.getParent+() = contract
  }

  /**
   * Holds if `func` makes any external calls.
   */
  predicate makesExternalCalls(Solidity::FunctionDefinition func) {
    exists(getExternalCallsInFunction(func))
  }

  /**
   * Holds if `func` makes low-level calls.
   */
  predicate makesLowLevelCalls(Solidity::FunctionDefinition func) {
    exists(ExternalCall call |
      call.getParent+() = func and
      call.isLowLevel()
    )
  }

  /**
   * Holds if `func` makes delegatecalls (high security risk).
   */
  predicate makesDelegateCalls(Solidity::FunctionDefinition func) {
    exists(ExternalCall call |
      call.getParent+() = func and
      call.isDelegateCall()
    )
  }
}
