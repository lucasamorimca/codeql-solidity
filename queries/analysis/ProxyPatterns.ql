/**
 * @name Proxy pattern analysis
 * @description Analyzes library usage, delegatecalls, and proxy patterns.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/proxy-patterns
 * @tags analysis
 *       proxy
 *       upgradeable
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.InheritanceGraph
import codeql.solidity.callgraph.ExternalCalls

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the library name.
 */
string getLibraryName(Solidity::LibraryDeclaration lib) {
  result = lib.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the interface name.
 */
string getInterfaceName(Solidity::InterfaceDeclaration iface) {
  result = iface.getName().(Solidity::AstNode).getValue()
}

/**
 * Detects using-for directives.
 * Output: JSON with type, contract, library, applied_to, file, line
 */
string formatUsingFor(Solidity::UsingDirective using) {
  exists(Solidity::ContractDeclaration contract, string libName, string appliedTo |
    using.getParent+() = contract and
    (
      exists(Solidity::Identifier libId |
        libId.getParent+() = using and
        libName = libId.getValue()
      )
      or
      not exists(Solidity::Identifier libId | libId.getParent+() = using) and
      libName = "unknown"
    ) and
    (
      exists(Solidity::AstNode typeNode |
        typeNode.getParent() = using and
        typeNode.toString() != "Identifier" and
        appliedTo = typeNode.toString()
      )
      or
      not exists(Solidity::AstNode typeNode |
        typeNode.getParent() = using and
        typeNode.toString() != "Identifier"
      ) and
      appliedTo = "*"
    ) and
    result =
      "{\"type\":\"using_for\",\"contract\":\"" + getContractName(contract) + "\",\"library\":\""
        + libName + "\",\"applied_to\":\"" + appliedTo + "\",\"file\":\""
        + using.getLocation().getFile().getName() + "\",\"line\":\""
        + using.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects library definitions.
 * Output: JSON with type, name, function_count, file, line
 */
string formatLibrary(Solidity::LibraryDeclaration lib) {
  exists(int funcCount |
    funcCount = count(Solidity::FunctionDefinition f | f.getParent+() = lib) and
    result =
      "{\"type\":\"library\",\"name\":\"" + getLibraryName(lib) + "\",\"function_count\":\""
        + funcCount.toString() + "\",\"file\":\"" + lib.getLocation().getFile().getName()
        + "\",\"line\":\"" + lib.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects delegatecall operations.
 * Output: JSON with type, contract, function, file, line
 */
string formatDelegatecall(Solidity::CallExpression call) {
  ExternalCalls::isDelegateCall(call) and
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract |
    call.getParent+() = func and
    func.getParent+() = contract and
    result =
      "{\"type\":\"delegatecall\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"file\":\"" + call.getLocation().getFile().getName()
        + "\",\"line\":\"" + call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects implementation address state variables.
 * Output: JSON with type, contract, variable, type, file, line
 */
string formatImplementationSlot(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string varType |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    varType = var.getType().(Solidity::AstNode).toString() and
    (
      varName.toLowerCase().matches("%implementation%") or
      varName.toLowerCase().matches("%logic%") or
      varName.toLowerCase().matches("%target%") or
      varName.toLowerCase().matches("%beacon%")
    ) and
    varType.toLowerCase().matches("%address%") and
    result =
      "{\"type\":\"impl_slot\",\"contract\":\"" + getContractName(contract) + "\",\"variable\":\""
        + varName + "\",\"type\":\"" + varType + "\",\"file\":\""
        + var.getLocation().getFile().getName() + "\",\"line\":\""
        + var.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects EIP-1967 implementation slot usage.
 * Output: JSON with type, contract, slot_type, file, line
 */
string formatEIP1967Slot(Solidity::AstNode node) {
  exists(Solidity::ContractDeclaration contract, string slotType |
    node.getParent+() = contract and
    (
      // Implementation slot
      node.getValue()
          .matches("%360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc%") and
      slotType = "implementation"
      or
      // Admin slot
      node.getValue()
          .matches("%b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103%") and
      slotType = "admin"
      or
      // Beacon slot
      node.getValue()
          .matches("%a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50%") and
      slotType = "beacon"
    ) and
    result =
      "{\"type\":\"eip1967\",\"contract\":\"" + getContractName(contract) + "\",\"slot_type\":\""
        + slotType + "\",\"file\":\"" + node.getLocation().getFile().getName()
        + "\",\"line\":\"" + node.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects proxy patterns based on inheritance.
 * Output: JSON with type, contract, pattern_type, inherited_from, file, line
 */
string formatProxyPattern(Solidity::ContractDeclaration contract) {
  exists(Solidity::ContractDeclaration base, string patternType |
    base = InheritanceGraph::getInheritanceChain(contract) and
    base != contract and
    (
      getContractName(base).toLowerCase().matches("%uupsupgradeable%") and
      patternType = "UUPS"
      or
      getContractName(base).toLowerCase().matches("%transparentupgradeableproxy%") and
      patternType = "Transparent"
      or
      getContractName(base).toLowerCase().matches("%erc1967%") and
      patternType = "EIP-1967"
      or
      getContractName(base).toLowerCase().matches("%beacon%") and
      patternType = "Beacon"
      or
      getContractName(base).toLowerCase().matches("%proxy%") and
      not getContractName(base).toLowerCase().matches("%transparent%") and
      not getContractName(base).toLowerCase().matches("%uups%") and
      patternType = "Generic Proxy"
    ) and
    result =
      "{\"type\":\"proxy_pattern\",\"contract\":\"" + getContractName(contract)
        + "\",\"pattern_type\":\"" + patternType + "\",\"inherited_from\":\""
        + getContractName(base) + "\",\"file\":\"" + contract.getLocation().getFile().getName()
        + "\",\"line\":\"" + contract.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Detects diamond/facet patterns.
 * Output: JSON with type, contract, indicator, file, line
 */
string formatDiamondPattern(Solidity::ContractDeclaration contract) {
  (
    getContractName(contract).toLowerCase().matches("%diamond%") or
    getContractName(contract).toLowerCase().matches("%facet%")
  ) and
  result =
    "{\"type\":\"diamond\",\"contract\":\"" + getContractName(contract) + "\",\"indicator\":\"name_pattern\",\"file\":\""
      + contract.getLocation().getFile().getName() + "\",\"line\":\""
      + contract.getLocation().getStartLine().toString() + "\"}"
}

// Main query
from string info
where
  info = formatUsingFor(_)
  or
  info = formatLibrary(_)
  or
  info = formatDelegatecall(_)
  or
  info = formatImplementationSlot(_)
  or
  info = formatEIP1967Slot(_)
  or
  info = formatProxyPattern(_)
  or
  info = formatDiamondPattern(_)
select info, info
