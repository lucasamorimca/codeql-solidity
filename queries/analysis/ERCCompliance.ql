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
 * Output: contract_func|contract|name|visibility|mutability|params|file:line
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
      "contract_func|" + getContractName(contract) + "|" + getFunctionName(func) + "|" + visibility
        + "|" + mutability + "|" + params.toString() + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Interface function.
 * Output: interface_func|interface|name|visibility|mutability|params|file:line
 */
string formatInterfaceFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::InterfaceDeclaration iface, string visibility, string mutability, int params |
    func.getParent+() = iface and
    visibility = getFunctionVisibility(func) and
    mutability = getFunctionMutability(func) and
    params = getParamCount(func) and
    result =
      "interface_func|" + getInterfaceName(iface) + "|" + getFunctionName(func) + "|" + visibility +
        "|" + mutability + "|" + params.toString() + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Event definition with parameters.
 * Output: event|contract|name|param_count|file:line
 */
string formatEvent(Solidity::EventDefinition event) {
  exists(Solidity::ContractDeclaration contract, int paramCount |
    event.getParent+() = contract and
    paramCount = count(Solidity::EventParameter p | p.getParent() = event) and
    result =
      "event|" + getContractName(contract) + "|" + event.getName().(Solidity::AstNode).getValue() +
        "|" + paramCount.toString() + "|" + event.getLocation().getFile().getName() + ":" +
        event.getLocation().getStartLine().toString()
  )
  or
  exists(Solidity::InterfaceDeclaration iface, int paramCount |
    event.getParent+() = iface and
    paramCount = count(Solidity::EventParameter p | p.getParent() = event) and
    result =
      "event|" + getInterfaceName(iface) + "|" + event.getName().(Solidity::AstNode).getValue() +
        "|" + paramCount.toString() + "|" + event.getLocation().getFile().getName() + ":" +
        event.getLocation().getStartLine().toString()
  )
}

/**
 * Import statement.
 * Output: import|path|file:line
 */
string formatImport(Solidity::ImportDirective imp) {
  exists(string path |
    path = imp.getSource().(Solidity::AstNode).getValue() and
    result =
      "import|" + path + "|" + imp.getLocation().getFile().getName() + ":" +
        imp.getLocation().getStartLine().toString()
  )
}

/**
 * Inheritance specifier (what a contract inherits from).
 * Output: inherits|contract|base|file:line
 */
string formatInheritance(Solidity::InheritanceSpecifier spec) {
  exists(Solidity::ContractDeclaration contract, Solidity::Identifier baseId |
    spec.getParent() = contract and
    baseId = spec.getAncestor().getAChild*() and
    result =
      "inherits|" + getContractName(contract) + "|" + baseId.getValue() + "|" +
        spec.getLocation().getFile().getName() + ":" +
        spec.getLocation().getStartLine().toString()
  )
}

/**
 * ERC-20 compliance indicator.
 * Output: erc20_func|contract|name|has_func
 */
string formatERC20Compliance(Solidity::ContractDeclaration contract) {
  exists(string funcName |
    isERC20Function(funcName) and
    (
      exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "erc20_func|" + getContractName(contract) + "|" + funcName + "|true"
      or
      not exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "erc20_func|" + getContractName(contract) + "|" + funcName + "|false"
    )
  )
}

/**
 * ERC-721 compliance indicator.
 */
string formatERC721Compliance(Solidity::ContractDeclaration contract) {
  exists(string funcName |
    isERC721Function(funcName) and
    (
      exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "erc721_func|" + getContractName(contract) + "|" + funcName + "|true"
      or
      not exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "erc721_func|" + getContractName(contract) + "|" + funcName + "|false"
    )
  )
}

/**
 * ERC-1155 compliance indicator.
 */
string formatERC1155Compliance(Solidity::ContractDeclaration contract) {
  exists(string funcName |
    isERC1155Function(funcName) and
    (
      exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "erc1155_func|" + getContractName(contract) + "|" + funcName + "|true"
      or
      not exists(Solidity::FunctionDefinition func |
        func.getParent+() = contract and
        getFunctionName(func) = funcName
      ) and
      result = "erc1155_func|" + getContractName(contract) + "|" + funcName + "|false"
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
