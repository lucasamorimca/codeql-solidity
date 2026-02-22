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
 * Output: JSON with type, name, is_abstract, direct_parents, depth, file, line
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
      "{\"type\":\"contract\",\"name\":\"" + getContractName(contract) + "\",\"is_abstract\":\""
        + isAbstract + "\",\"direct_parents\":\"" + parents + "\",\"depth\":\""
        + depth.toString() + "\",\"file\":\"" + contract.getLocation().getFile().getName()
        + "\",\"line\":\"" + contract.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Interface information.
 * Output: JSON with type, name, is_abstract, parents, depth, file, line
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
      "{\"type\":\"interface\",\"name\":\"" + getInterfaceName(iface) + "\",\"is_abstract\":\"false\",\"parents\":\""
        + parents + "\",\"depth\":\"0\",\"file\":\"" + iface.getLocation().getFile().getName()
        + "\",\"line\":\"" + iface.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Library information.
 * Output: JSON with type, name, is_abstract, parents, depth, file, line
 */
string formatLibraryInfo(Solidity::LibraryDeclaration lib) {
  result =
    "{\"type\":\"library\",\"name\":\"" + getLibraryName(lib) + "\",\"is_abstract\":\"false\",\"parents\":\"\",\"depth\":\"0\",\"file\":\""
      + lib.getLocation().getFile().getName() + "\",\"line\":\""
      + lib.getLocation().getStartLine().toString() + "\"}"
}

/**
 * Overridden function information.
 * Output: JSON with type, func_name, declaring_contract, overrides_contract, visibility, file, line
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
      "{\"type\":\"override\",\"func_name\":\"" + getFunctionName(func) + "\",\"declaring_contract\":\""
        + getContractName(contract) + "\",\"overrides_contract\":\""
        + getContractName(overridden.getParent+()) + "\",\"visibility\":\"" + visibility
        + "\",\"file\":\"" + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Virtual function information.
 * Output: JSON with type, func_name, contract, visibility, file, line
 */
string formatVirtualFunction(Solidity::FunctionDefinition func) {
  InheritanceGraph::isVirtualFunction(func) and
  exists(Solidity::ContractDeclaration contract, string visibility |
    func.getParent+() = contract and
    visibility = getFunctionVisibility(func) and
    result =
      "{\"type\":\"virtual\",\"func_name\":\"" + getFunctionName(func) + "\",\"contract\":\""
        + getContractName(contract) + "\",\"visibility\":\"" + visibility + "\",\"file\":\""
        + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Diamond inheritance detection.
 * Output: JSON with type, contract, repeated_base
 */
string formatDiamondInheritance(Solidity::ContractDeclaration contract) {
  exists(Solidity::ContractDeclaration base |
    // Count how many times this base appears in inheritance paths
    count(Solidity::ContractDeclaration intermediate |
      InheritanceGraph::inheritsFrom(contract, intermediate) and
      InheritanceGraph::inheritsFrom(intermediate, base)
    ) > 1 and
    result = "{\"type\":\"diamond\",\"contract\":\"" + getContractName(contract)
      + "\",\"repeated_base\":\"" + getContractName(base) + "\"}"
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
