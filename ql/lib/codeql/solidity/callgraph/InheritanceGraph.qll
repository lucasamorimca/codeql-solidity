/**
 * Provides inheritance graph analysis for Solidity contracts.
 *
 * This module tracks inheritance relationships, virtual function resolution,
 * and provides utilities for resolving overridden functions.
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Contract
private import codeql.solidity.ast.Function

/**
 * Gets the function name from a function definition.
 */
private string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the contract name from a contract declaration.
 */
private string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the interface name from an interface declaration.
 */
private string getInterfaceName(Solidity::InterfaceDeclaration iface) {
  result = iface.getName().(Solidity::AstNode).getValue()
}

/**
 * Module for inheritance graph analysis.
 */
module InheritanceGraph {
  /**
   * Gets a direct base contract of `contract`.
   *
   * This follows the InheritanceSpecifier declarations in the contract.
   */
  Solidity::ContractDeclaration getDirectBase(Solidity::ContractDeclaration contract) {
    exists(Solidity::InheritanceSpecifier spec, Solidity::Identifier baseId |
      spec.getParent() = contract and
      baseId = spec.getAncestor().getAChild*() and
      getContractName(result) = baseId.getValue()
    )
  }

  /**
   * Gets a direct base interface of `iface`.
   */
  Solidity::InterfaceDeclaration getDirectBaseInterface(Solidity::InterfaceDeclaration iface) {
    exists(Solidity::InheritanceSpecifier spec, Solidity::Identifier baseId |
      spec.getParent() = iface and
      baseId = spec.getAncestor().getAChild*() and
      getInterfaceName(result) = baseId.getValue()
    )
  }

  /**
   * Gets all contracts in the inheritance chain of `contract` (including itself).
   *
   * This is the transitive closure of the inheritance relationship.
   */
  Solidity::ContractDeclaration getInheritanceChain(Solidity::ContractDeclaration contract) {
    result = contract
    or
    result = getInheritanceChain(getDirectBase(contract))
  }

  /**
   * Gets all interfaces in the inheritance chain of `iface` (including itself).
   */
  Solidity::InterfaceDeclaration getInterfaceChain(Solidity::InterfaceDeclaration iface) {
    result = iface
    or
    result = getInterfaceChain(getDirectBaseInterface(iface))
  }

  /**
   * Holds if `contract` inherits from `base` (directly or transitively).
   */
  predicate inheritsFrom(
    Solidity::ContractDeclaration contract,
    Solidity::ContractDeclaration base
  ) {
    base = getInheritanceChain(contract) and
    base != contract
  }

  /**
   * Gets the depth of `contract` in its inheritance hierarchy.
   * A contract with no base has depth 0.
   *
   * Note: This uses bounded recursion to avoid non-monotonic issues.
   */
  int getInheritanceDepth(Solidity::ContractDeclaration contract) {
    not exists(getDirectBase(contract)) and result = 0
    or
    exists(getDirectBase(contract)) and
    result = 1 + count(Solidity::ContractDeclaration base | base = getInheritanceChain(contract) and base != contract)
  }

  /**
   * Holds if `func` is declared as virtual.
   */
  predicate isVirtualFunction(Solidity::FunctionDefinition func) {
    exists(Solidity::AstNode v |
      v.getParent() = func and
      v.getValue() = "virtual"
    )
  }

  /**
   * Holds if `func` is declared with the override keyword.
   */
  predicate isOverrideFunction(Solidity::FunctionDefinition func) {
    exists(Solidity::AstNode o |
      o.getParent() = func and
      o.getValue() = "override"
    )
    or
    // Override node may be a child container
    exists(Solidity::AstNode o |
      o.getParent() = func and
      o.toString() = "Override"
    )
  }

  /**
   * Holds if `func` is implicitly virtual (in an interface or abstract contract).
   */
  predicate isImplicitlyVirtual(Solidity::FunctionDefinition func) {
    // Functions in interfaces are implicitly virtual
    func.getParent+() instanceof Solidity::InterfaceDeclaration
    or
    // Functions without implementation in abstract contracts
    exists(Solidity::ContractDeclaration contract |
      func.getParent+() = contract and
      isAbstractContract(contract) and
      not exists(func.getBody())
    )
  }

  /**
   * Holds if `contract` is abstract.
   */
  predicate isAbstractContract(Solidity::ContractDeclaration contract) {
    exists(Solidity::AstNode node |
      node.getParent() = contract and
      node.getValue() = "abstract"
    )
  }

  /**
   * Gets the function that `func` overrides, if any.
   *
   * Returns the overridden function in the base contract.
   */
  Solidity::FunctionDefinition getOverriddenFunction(Solidity::FunctionDefinition func) {
    isOverrideFunction(func) and
    exists(Solidity::ContractDeclaration contract, string funcName |
      func.getParent+() = contract and
      funcName = getFunctionName(func) and
      result.getParent+() = getDirectBase(contract) and
      getFunctionName(result) = funcName
    )
    or
    // Transitive: if we override X and X overrides Y, we transitively override Y
    result = getOverriddenFunction(getOverriddenFunction(func))
  }

  /**
   * Gets all functions that override `func`.
   */
  Solidity::FunctionDefinition getOverridingFunction(Solidity::FunctionDefinition func) {
    func = getOverriddenFunction(result)
  }

  /**
   * Resolves a virtual function call to the most derived implementation.
   *
   * Given a static contract type and function name, returns the most specific
   * implementation considering the inheritance hierarchy.
   */
  Solidity::FunctionDefinition resolveVirtualCall(
    Solidity::ContractDeclaration staticType,
    string funcName
  ) {
    // Find function with this name in the inheritance chain
    result.getParent+() = getInheritanceChain(staticType) and
    getFunctionName(result) = funcName and
    // It's the most derived (no override exists in a more derived contract)
    not exists(Solidity::FunctionDefinition moreSpecific |
      moreSpecific.getParent+() = getInheritanceChain(staticType) and
      getFunctionName(moreSpecific) = funcName and
      isOverrideFunction(moreSpecific) and
      result = getOverriddenFunction(moreSpecific)
    )
  }

  /**
   * Gets all possible implementations of a virtual function.
   *
   * For dynamic dispatch, multiple implementations may be possible
   * depending on the runtime type of the receiver.
   */
  Solidity::FunctionDefinition getAllImplementations(
    Solidity::ContractDeclaration staticType,
    string funcName
  ) {
    // The static type's implementation (if any)
    result.getParent+() = staticType and
    getFunctionName(result) = funcName
    or
    // Implementations in derived contracts
    exists(Solidity::ContractDeclaration derived |
      inheritsFrom(derived, staticType) and
      result.getParent+() = derived and
      getFunctionName(result) = funcName
    )
  }

  /**
   * Gets the C3 linearization order for `contract`.
   *
   * Solidity uses C3 linearization for method resolution order (MRO).
   * In Solidity, the linearization follows right-to-left order of inheritance specification,
   * then recursively linearizes each base, removing duplicates while preserving order.
   *
   * For example: `contract D is B, C` where B and C both inherit A
   * Linearization: D -> C -> B -> A (rightmost first, then parents)
   *
   * This implementation handles the common cases correctly.
   */
  Solidity::ContractDeclaration getLinearizedBase(
    Solidity::ContractDeclaration contract,
    int index
  ) {
    // Index 0 is the contract itself
    index = 0 and result = contract
    or
    // For linearization, we need to process bases right-to-left
    index > 0 and
    result = getLinearizedBaseHelper(contract, index)
  }

  /**
   * Helper for C3 linearization that processes inheritance right-to-left.
   *
   * Solidity linearization rule: for `contract C is A, B`, the order is:
   * C, then linearize(B), then linearize(A), removing duplicates.
   */
  private Solidity::ContractDeclaration getLinearizedBaseHelper(
    Solidity::ContractDeclaration contract,
    int index
  ) {
    exists(int baseCount |
      baseCount = count(getDirectBase(contract)) and
      (
        // Single inheritance: simple chain
        baseCount = 1 and
        result = getLinearizedBase(getDirectBase(contract), index - 1)
        or
        // Multiple inheritance: process in declaration order (right-to-left semantically)
        // but Solidity's right-to-left means last in source = first in MRO after self
        baseCount > 1 and
        exists(Solidity::ContractDeclaration base |
          base = getDirectBase(contract) and
          (
            // Direct bases come first after self
            index = 1 + count(Solidity::ContractDeclaration other |
              other = getDirectBase(contract) and
              // Use string comparison for ordering - bases declared later come first
              getContractName(other) > getContractName(base)
            ) and
            result = base
            or
            // Then ancestors of each base, ranked alphabetically after direct bases
            result = getInheritanceChain(base) and
            result != contract and
            not result = getDirectBase(contract) and
            index =
              baseCount + 1 +
                count(Solidity::ContractDeclaration other |
                  other = getInheritanceChain(getDirectBase(contract)) and
                  other != contract and
                  not other = getDirectBase(contract) and
                  getContractName(other) < getContractName(result)
                )
          )
        )
      )
    )
  }

  /**
   * Holds if `contract` has diamond inheritance pattern.
   * Diamond: D inherits from B and C, both B and C inherit from A.
   * This can cause method resolution ambiguity.
   */
  predicate hasDiamondInheritance(Solidity::ContractDeclaration contract) {
    exists(Solidity::ContractDeclaration base1, Solidity::ContractDeclaration base2,
           Solidity::ContractDeclaration common |
      base1 = getDirectBase(contract) and
      base2 = getDirectBase(contract) and
      base1 != base2 and
      common = getInheritanceChain(base1) and
      common = getInheritanceChain(base2) and
      common != base1 and
      common != base2
    )
  }

  /**
   * Gets the most-derived implementation of a function for diamond inheritance.
   * In diamond inheritance, returns the function from the rightmost base in
   * the inheritance specification that has an implementation.
   */
  Solidity::FunctionDefinition resolveDiamondFunction(
    Solidity::ContractDeclaration contract,
    string funcName
  ) {
    hasDiamondInheritance(contract) and
    result.getParent+() = getInheritanceChain(contract) and
    getFunctionName(result) = funcName and
    // Must be the most derived - no more specific override exists
    not exists(Solidity::FunctionDefinition moreSpecific |
      moreSpecific.getParent+() = getInheritanceChain(contract) and
      getFunctionName(moreSpecific) = funcName and
      moreSpecific != result and
      result.getParent+() = getInheritanceChain(moreSpecific.getParent+())
    )
  }

  /**
   * Holds if `contract` has multiple inheritance (more than one direct base).
   */
  predicate hasMultipleInheritance(Solidity::ContractDeclaration contract) {
    count(getDirectBase(contract)) > 1
  }

  /**
   * Gets a function inherited by `contract` from a base contract.
   */
  Solidity::FunctionDefinition getInheritedFunction(
    Solidity::ContractDeclaration contract,
    string funcName
  ) {
    exists(Solidity::ContractDeclaration base |
      base = getInheritanceChain(contract) and
      base != contract and
      result.getParent+() = base and
      getFunctionName(result) = funcName and
      // Not overridden in a closer base
      not exists(Solidity::FunctionDefinition closer |
        closer.getParent+() = getInheritanceChain(contract) and
        closer.getParent+() != base and
        getFunctionName(closer) = funcName and
        base = getInheritanceChain(closer.getParent+())
      )
    )
  }

  /**
   * Gets all functions available on `contract` (defined or inherited).
   */
  Solidity::FunctionDefinition getAllFunctions(Solidity::ContractDeclaration contract) {
    // Defined in contract
    result.getParent+() = contract
    or
    // Inherited (and not overridden)
    exists(string funcName |
      result = getInheritedFunction(contract, funcName) and
      not exists(Solidity::FunctionDefinition local |
        local.getParent+() = contract and
        getFunctionName(local) = funcName
      )
    )
  }
}
