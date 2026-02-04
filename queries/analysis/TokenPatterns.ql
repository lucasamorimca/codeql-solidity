/**
 * @name Token pattern analysis
 * @description Analyzes token patterns: SafeERC20, transfers, approvals.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/token-patterns
 * @tags analysis
 *       tokens
 *       erc20
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
 * Gets the function name.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Detects SafeERC20 usage via using-for directive.
 * Output: safe_erc20|contract|library|applied_to|file:line
 */
string formatSafeERC20Usage(Solidity::UsingDirective using) {
  exists(Solidity::ContractDeclaration contract, Solidity::Identifier libId |
    using.getParent+() = contract and
    libId.getParent+() = using and
    (
      libId.getValue().matches("%SafeERC20%") or
      libId.getValue().matches("%SafeTransfer%")
    ) and
    result =
      "safe_erc20|" + getContractName(contract) + "|" + libId.getValue() + "|" +
        using.getLocation().getFile().getName() + ":" +
        using.getLocation().getStartLine().toString()
  )
}

/**
 * Detects direct transfer/transferFrom calls (potentially unsafe).
 * Output: direct_transfer|contract|function|call_type|file:line
 */
string formatDirectTransfer(Solidity::CallExpression call) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::MemberExpression member, string callType
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    member = call.getFunction().getAChild*() and
    callType = member.getProperty().(Solidity::AstNode).getValue() and
    callType in ["transfer", "transferFrom", "approve"] and
    // Check it's not a safe variant
    not exists(Solidity::Identifier safe |
      safe.getParent+() = call and
      safe.getValue().toLowerCase().matches("%safe%")
    ) and
    result =
      "direct_transfer|" + getContractName(contract) + "|" + getFunctionName(func) + "|" +
        callType + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Detects safe transfer calls (safeTransfer, safeTransferFrom, safeApprove).
 * Output: safe_transfer|contract|function|call_type|file:line
 */
string formatSafeTransfer(Solidity::CallExpression call) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::MemberExpression member, string callType
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    member = call.getFunction().getAChild*() and
    callType = member.getProperty().(Solidity::AstNode).getValue() and
    (
      callType.matches("safeTransfer%") or
      callType.matches("safeApprove%") or
      callType = "forceApprove"
    ) and
    result =
      "safe_transfer|" + getContractName(contract) + "|" + getFunctionName(func) + "|" + callType +
        "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Detects ERC20 interface implementations.
 * Output: erc20_impl|contract|function|file:line
 */
string formatERC20Implementation(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    funcName in [
        "transfer", "transferFrom", "approve", "allowance", "balanceOf", "totalSupply", "name",
        "symbol", "decimals"
      ] and
    result =
      "erc20_impl|" + getContractName(contract) + "|" + funcName + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Detects ERC721 interface implementations.
 * Output: erc721_impl|contract|function|file:line
 */
string formatERC721Implementation(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    funcName in [
        "ownerOf", "safeTransferFrom", "setApprovalForAll", "getApproved", "isApprovedForAll",
        "tokenURI", "tokenByIndex", "tokenOfOwnerByIndex"
      ] and
    result =
      "erc721_impl|" + getContractName(contract) + "|" + funcName + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Detects token-related state variables.
 * Output: token_var|contract|name|type|file:line
 */
string formatTokenVariable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string varType |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    varType = var.getType().(Solidity::AstNode).toString() and
    (
      varType.matches("%IERC20%") or
      varType.matches("%ERC20%") or
      varType.matches("%IERC721%") or
      varType.matches("%ERC721%") or
      varType.matches("%IERC1155%") or
      varName.toLowerCase().matches("%token%")
    ) and
    result =
      "token_var|" + getContractName(contract) + "|" + varName + "|" + varType + "|" +
        var.getLocation().getFile().getName() + ":" + var.getLocation().getStartLine().toString()
  )
}

/**
 * Detects approve(0) before approve(amount) pattern (for USDT compatibility).
 * This is a heuristic based on finding approve calls.
 * Output: approve_call|contract|function|file:line
 */
string formatApproveCall(Solidity::CallExpression call) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::MemberExpression member
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    member = call.getFunction().getAChild*() and
    member.getProperty().(Solidity::AstNode).getValue() = "approve" and
    result =
      "approve_call|" + getContractName(contract) + "|" + getFunctionName(func) + "|" +
        call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Detects mint/burn functions.
 * Output: mint_burn|contract|function|type|file:line
 */
string formatMintBurn(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName, string funcType |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    (
      funcName.toLowerCase().matches("%mint%") and funcType = "mint"
      or
      funcName.toLowerCase().matches("%burn%") and funcType = "burn"
    ) and
    result =
      "mint_burn|" + getContractName(contract) + "|" + funcName + "|" + funcType + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Detects permit functions (ERC20Permit).
 * Output: permit|contract|function|file:line
 */
string formatPermit(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    funcName.toLowerCase().matches("%permit%") and
    result =
      "permit|" + getContractName(contract) + "|" + funcName + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Detects unchecked return value from transfer calls.
 * Output: unchecked_return|contract|function|file:line
 */
string formatUncheckedReturn(Solidity::CallExpression call) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::MemberExpression member, string methodName
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    member = call.getFunction().getAChild*() and
    methodName = member.getProperty().(Solidity::AstNode).getValue() and
    methodName in ["transfer", "transferFrom", "approve"] and
    // Call is a statement (return value not used)
    call.getParent() instanceof Solidity::ExpressionStatement and
    result =
      "unchecked_return|" + getContractName(contract) + "|" + getFunctionName(func) + "|" +
        call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatSafeERC20Usage(_)
  or
  info = formatDirectTransfer(_)
  or
  info = formatSafeTransfer(_)
  or
  info = formatERC20Implementation(_)
  or
  info = formatERC721Implementation(_)
  or
  info = formatTokenVariable(_)
  or
  info = formatApproveCall(_)
  or
  info = formatMintBurn(_)
  or
  info = formatPermit(_)
  or
  info = formatUncheckedReturn(_)
select info, info
