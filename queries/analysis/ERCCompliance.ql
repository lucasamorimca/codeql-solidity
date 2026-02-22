/**
 * @name ERC standard compliance analysis
 * @description Analyzes ERC-20, ERC-721, ERC-1155 compliance.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/erc-compliance
 * @tags analysis
 *       erc
 *       standards
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the contract name.
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
 * Gets the function name.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
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
  result = "internal"
}

/**
 * Gets mutability (view, pure, payable).
 */
string getFunctionMutability(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode mut |
    mut.getParent() = func and
    mut.getValue() in ["view", "pure", "payable"] and
    result = mut.getValue()
  )
  or
  not exists(Solidity::AstNode mut |
    mut.getParent() = func and
    mut.getValue() in ["view", "pure", "payable"]
  ) and
  result = "nonpayable"
}

/**
 * Gets parameter count.
 */
int getParamCount(Solidity::FunctionDefinition func) {
  result = count(Solidity::Parameter p | p.getParent() = func)
}

/**
 * ERC-20 required functions.
 */
predicate isERC20Function(string name) {
  name in [
      "totalSupply", "balanceOf", "transfer", "transferFrom", "approve", "allowance", "name",
      "symbol", "decimals"
    ]
}

/**
 * ERC-721 required functions.
 */
predicate isERC721Function(string name) {
  name in [
      "balanceOf", "ownerOf", "safeTransferFrom", "transferFrom", "approve", "setApprovalForAll",
      "getApproved", "isApprovedForAll", "name", "symbol", "tokenURI", "supportsInterface"
    ]
}

/**
 * ERC-1155 required functions.
 */
predicate isERC1155Function(string name) {
  name in [
      "balanceOf", "balanceOfBatch", "setApprovalForAll", "isApprovedForAll", "safeTransferFrom",
      "safeBatchTransferFrom", "uri", "supportsInterface"
    ]
}

/**
 * Contract function (for compliance checking).
 * Output: JSON with type, contract, name, visibility, mutability, params, file, line
 */
string formatContractFunction(Solidity::FunctionDefinition func) {
  exists(
    Solidity::ContractDeclaration contract, string visibility, string mutability, int params
  |
    func.getParent+() = contract and
    visibility = getFunctionVisibility(func) and
    mutability = getFunctionMutability(func) and
    params = getParamCount(func) and
    result =
      "{\"type\":\"contract_func\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + getFunctionName(func) + "\",\"visibility\":\"" + visibility + "\",\"mutability\":\""
        + mutability + "\",\"params\":\"" + params.toString() + "\",\"file\":\""
        + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Interface function.
 * Output: JSON with type, interface, name, visibility, mutability, params, file, line
 */
string formatInterfaceFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::InterfaceDeclaration iface, string visibility, string mutability, int params |
    func.getParent+() = iface and
    visibility = getFunctionVisibility(func) and
    mutability = getFunctionMutability(func) and
    params = getParamCount(func) and
    result =
      "{\"type\":\"interface_func\",\"interface\":\"" + getInterfaceName(iface) + "\",\"name\":\""
        + getFunctionName(func) + "\",\"visibility\":\"" + visibility + "\",\"mutability\":\""
        + mutability + "\",\"params\":\"" + params.toString() + "\",\"file\":\""
        + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Event definition with parameters.
 * Output: JSON with type, contract_or_interface, name, param_count, file, line
 */
string formatEvent(Solidity::EventDefinition event) {
  exists(Solidity::ContractDeclaration contract, int paramCount |
    event.getParent+() = contract and
    paramCount = count(Solidity::EventParameter p | p.getParent() = event) and
    result =
      "{\"type\":\"event\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + event.getName().(Solidity::AstNode).getValue() + "\",\"param_count\":\""
        + paramCount.toString() + "\",\"file\":\"" + event.getLocation().getFile().getName()
        + "\",\"line\":\"" + event.getLocation().getStartLine().toString() + "\"}"
  )
  or
  exists(Solidity::InterfaceDeclaration iface, int paramCount |
    event.getParent+() = iface and
    paramCount = count(Solidity::EventParameter p | p.getParent() = event) and
    result =
      "{\"type\":\"event\",\"interface\":\"" + getInterfaceName(iface) + "\",\"name\":\""
        + event.getName().(Solidity::AstNode).getValue() + "\",\"param_count\":\""
        + paramCount.toString() + "\",\"file\":\"" + event.getLocation().getFile().getName()
        + "\",\"line\":\"" + event.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Import statement.
 * Output: JSON with type, path, file, line
 */
string formatImport(Solidity::ImportDirective imp) {
  exists(string path |
    path = imp.getSource().(Solidity::AstNode).getValue() and
    result =
      "{\"type\":\"import\",\"path\":\"" + path + "\",\"file\":\""
        + imp.getLocation().getFile().getName() + "\",\"line\":\""
        + imp.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Inheritance specifier (what a contract inherits from).
 * Output: JSON with type, contract, base, file, line
 */
string formatInheritance(Solidity::InheritanceSpecifier spec) {
  exists(Solidity::ContractDeclaration contract, Solidity::Identifier baseId |
    spec.getParent() = contract and
    baseId = spec.getAncestor().getAChild*() and
    result =
      "{\"type\":\"inherits\",\"contract\":\"" + getContractName(contract) + "\",\"base\":\""
        + baseId.getValue() + "\",\"file\":\"" + spec.getLocation().getFile().getName()
        + "\",\"line\":\"" + spec.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * ERC-20 compliance indicator.
 * Output: JSON with type, contract, name, has_func
 */
string formatERC20Compliance(Solidity::ContractDeclaration contract) {
  exists(string funcName |
    isERC20Function(funcName) and
    (
      exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "{\"type\":\"erc20_func\",\"contract\":\"" + getContractName(contract)
        + "\",\"name\":\"" + funcName + "\",\"has_func\":\"true\"}"
      or
      not exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "{\"type\":\"erc20_func\",\"contract\":\"" + getContractName(contract)
        + "\",\"name\":\"" + funcName + "\",\"has_func\":\"false\"}"
    )
  )
}

/**
 * ERC-721 compliance indicator.
 * Output: JSON with type, contract, name, has_func
 */
string formatERC721Compliance(Solidity::ContractDeclaration contract) {
  exists(string funcName |
    isERC721Function(funcName) and
    (
      exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "{\"type\":\"erc721_func\",\"contract\":\"" + getContractName(contract)
        + "\",\"name\":\"" + funcName + "\",\"has_func\":\"true\"}"
      or
      not exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "{\"type\":\"erc721_func\",\"contract\":\"" + getContractName(contract)
        + "\",\"name\":\"" + funcName + "\",\"has_func\":\"false\"}"
    )
  )
}

/**
 * ERC-1155 compliance indicator.
 * Output: JSON with type, contract, name, has_func
 */
string formatERC1155Compliance(Solidity::ContractDeclaration contract) {
  exists(string funcName |
    isERC1155Function(funcName) and
    (
      exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "{\"type\":\"erc1155_func\",\"contract\":\"" + getContractName(contract)
        + "\",\"name\":\"" + funcName + "\",\"has_func\":\"true\"}"
      or
      not exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "{\"type\":\"erc1155_func\",\"contract\":\"" + getContractName(contract)
        + "\",\"name\":\"" + funcName + "\",\"has_func\":\"false\"}"
    )
  )
}

// Main query
from string info
where
  info = formatContractFunction(_)
  or
  info = formatInterfaceFunction(_)
  or
  info = formatEvent(_)
  or
  info = formatImport(_)
  or
  info = formatInheritance(_)
  or
  info = formatERC20Compliance(_)
  or
  info = formatERC721Compliance(_)
  or
  info = formatERC1155Compliance(_)
select info, info
