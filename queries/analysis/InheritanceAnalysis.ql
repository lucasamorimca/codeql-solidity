/**
 * @name Inheritance chain analysis
 * @description Analyzes inheritance hierarchies, overridden functions, and virtual functions.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/inheritance-analysis
 * @tags analysis
 *       inheritance
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.InheritanceGraph

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the interface name.
 */
string getInterfaceName(Solidity::InterfaceDeclaration iface) {
  result = iface.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the library name.
 */
string getLibraryName(Solidity::LibraryDeclaration lib) {
  result = lib.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets visibility of a function.
 */
string getFunctionVisibility(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility" and
    result = vis.getAChild().getValue()
  )
  or
  not exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility"
  ) and
  result = "public"
}

/**
 * Gets a modifier applied to a function.
 */
string getFunctionModifier(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent() = func and
    result = mod.getValue()
  )
}

/**
 * Contract inheritance information.
 * Output: type|name|is_abstract|direct_parents|depth|file:line
 */
string formatContractInheritance(Solidity::ContractDeclaration contract) {
  exists(string contractType, string isAbstract, string parents, int depth |
    contractType = "contract" and
    (
      if InheritanceGraph::isAbstractContract(contract)
      then isAbstract = "true"
      else isAbstract = "false"
    ) and
    parents =
      concat(Solidity::ContractDeclaration base |
        base = InheritanceGraph::getDirectBase(contract)
      |
        getContractName(base), ","
      ) and
    depth = InheritanceGraph::getInheritanceDepth(contract) and
    result =
      contractType + "|" + getContractName(contract) + "|" + isAbstract + "|" + parents + "|" +
        depth.toString() + "|" + contract.getLocation().getFile().getName() + ":" +
        contract.getLocation().getStartLine().toString()
  )
}

/**
 * Interface information.
 */
string formatInterfaceInfo(Solidity::InterfaceDeclaration iface) {
  exists(string parents |
    parents =
      concat(Solidity::InterfaceDeclaration base |
        base = InheritanceGraph::getDirectBaseInterface(iface)
      |
        getInterfaceName(base), ","
      ) and
    result =
      "interface|" + getInterfaceName(iface) + "|false|" + parents + "|0|" +
        iface.getLocation().getFile().getName() + ":" +
        iface.getLocation().getStartLine().toString()
  )
}

/**
 * Library information.
 */
string formatLibraryInfo(Solidity::LibraryDeclaration lib) {
  result =
    "library|" + getLibraryName(lib) + "|false||0|" + lib.getLocation().getFile().getName() + ":" +
      lib.getLocation().getStartLine().toString()
}

/**
 * Overridden function information.
 * Output: override|func_name|declaring_contract|overrides_contract|visibility|file:line
 */
string formatOverriddenFunction(Solidity::FunctionDefinition func) {
  InheritanceGraph::isOverrideFunction(func) and
  exists(
    Solidity::ContractDeclaration contract, Solidity::FunctionDefinition overridden,
    string visibility
  |
    func.getParent+() = contract and
    overridden = InheritanceGraph::getOverriddenFunction(func) and
    visibility = getFunctionVisibility(func) and
    result =
      "override|" + getFunctionName(func) + "|" + getContractName(contract) + "|" +
        getContractName(overridden.getParent+()) + "|" + visibility + "|" +
        func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Virtual function information.
 * Output: virtual|func_name|contract|visibility|file:line
 */
string formatVirtualFunction(Solidity::FunctionDefinition func) {
  InheritanceGraph::isVirtualFunction(func) and
  exists(Solidity::ContractDeclaration contract, string visibility |
    func.getParent+() = contract and
    visibility = getFunctionVisibility(func) and
    result =
      "virtual|" + getFunctionName(func) + "|" + getContractName(contract) + "|" + visibility + "|" +
        func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * Diamond inheritance detection.
 * Output: diamond|contract|repeated_base
 */
string formatDiamondInheritance(Solidity::ContractDeclaration contract) {
  exists(Solidity::ContractDeclaration base |
    // Count how many times this base appears in inheritance paths
    count(Solidity::ContractDeclaration intermediate |
      InheritanceGraph::inheritsFrom(contract, intermediate) and
      InheritanceGraph::inheritsFrom(intermediate, base)
    ) > 1 and
    result = "diamond|" + getContractName(contract) + "|" + getContractName(base)
  )
}

// Main query: output all inheritance information
from string info
where
  info = formatContractInheritance(_)
  or
  info = formatInterfaceInfo(_)
  or
  info = formatLibraryInfo(_)
  or
  info = formatOverriddenFunction(_)
  or
  info = formatVirtualFunction(_)
  or
  info = formatDiamondInheritance(_)
select info, info
