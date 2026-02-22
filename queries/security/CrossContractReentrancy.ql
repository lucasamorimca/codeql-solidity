/**
 * @name Cross-contract reentrancy detection
 * @description Detects cross-contract reentrancy patterns where Contract A calls Contract B, which can callback into Contract A
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/cross-contract-reentrancy
 * @tags security reentrancy cross-contract solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Holds if a function has a reentrancy guard modifier.
 */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%nonreentrant%") or
    mod.getValue().toLowerCase().matches("%lock%") or
    mod.getValue().toLowerCase().matches("%mutex%") or
    mod.getValue().toLowerCase().matches("%guard%")
  )
}

/**
 * Holds if `call` is an external call (low-level, contract reference, or ether transfer).
 */
private predicate isExternalCall(Solidity::CallExpression call) {
  ExternalCalls::isLowLevelCall(call) or
  ExternalCalls::isContractReferenceCall(call) or
  ExternalCalls::isEtherTransfer(call)
}

/**
 * Functions with external calls that lack reentrancy guards
 */
string formatUnguardedExternalCalls(
  Solidity::CallExpression extCall,
  Solidity::FunctionDefinition callerFunc,
  Solidity::ContractDeclaration callerContract
) {
  isExternalCall(extCall) and
  extCall.getParent+() = callerFunc and
  callerFunc.getParent+() = callerContract and
  not hasReentrancyGuard(callerFunc) and
  result =
    "{\"type\":\"unguarded_external_call\",\"contract\":\"" + getContractName(callerContract) +
    "\",\"function\":\"" + getFunctionName(callerFunc) +
    "\",\"location\":\"" + (extCall.getLocation().getFile().getName() + ":" + extCall.getLocation().getStartLine().toString()) + "\"}"
}

/**
 * Receive/fallback function detection (reentrancy entry points)
 */
string formatCallback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName, string location |
    func.getParent+() = contract and
    funcName = getFunctionName(func).toLowerCase() and
    (funcName = "receive" or funcName = "fallback") and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"callback\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + funcName +
      "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * ERC20 callback detection
 */
string formatERC20Callback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName, string location |
    func.getParent+() = contract and
    funcName = getFunctionName(func).toLowerCase() and
    (
      funcName = "tokensreceived" or
      funcName = "ontokentransfer" or
      funcName = "onerc721received" or
      funcName = "onerc1155received" or
      funcName.matches("%uniswapv2call%") or
      funcName.matches("%uniswapv3swapcallback%")
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"erc20_callback\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"location\":\"" + location + "\"}"
  )
}

// Main query
from string info
where
  info = formatUnguardedExternalCalls(_, _, _)
  or
  info = formatCallback(_)
  or
  info = formatERC20Callback(_)
select info, info
