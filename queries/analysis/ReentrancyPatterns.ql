/**
 * @name Reentrancy pattern analysis
 * @description Analyzes reentrancy patterns: external calls, state changes, CEI violations.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/reentrancy-patterns
 * @tags analysis
 *       reentrancy
 *       security
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls

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
 * Holds if a function has a nonReentrant modifier.
 */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent() = func and
    mod.getValue().toLowerCase().matches("%nonreentrant%")
  )
}

/**
 * Holds if a function has a mutex/lock modifier.
 */
predicate hasMutexGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent() = func and
    (
      mod.getValue().toLowerCase().matches("%lock%") or
      mod.getValue().toLowerCase().matches("%mutex%") or
      mod.getValue().toLowerCase().matches("%guard%")
    )
  )
}

/**
 * Gets the line number of an AST node.
 */
int getLine(Solidity::AstNode node) { result = node.getLocation().getStartLine() }

/**
 * External call detection.
 * Output: external_call|contract|function|call_type|has_guard|file:line
 */
string formatExternalCall(Solidity::CallExpression call) {
  (
    ExternalCalls::isLowLevelCall(call) or
    ExternalCalls::isContractReferenceCall(call) or
    ExternalCalls::isEtherTransfer(call)
  ) and
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string callType,
    string hasGuard
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    (
      ExternalCalls::isDelegateCall(call) and callType = "delegatecall"
      or
      ExternalCalls::isCall(call) and callType = "call"
      or
      ExternalCalls::isStaticCall(call) and callType = "staticcall"
      or
      ExternalCalls::isEtherTransfer(call) and callType = "transfer"
      or
      ExternalCalls::isContractReferenceCall(call) and
      not ExternalCalls::isLowLevelCall(call) and
      not ExternalCalls::isEtherTransfer(call) and
      callType = "high_level"
    ) and
    (
      if hasReentrancyGuard(func) or hasMutexGuard(func)
      then hasGuard = "true"
      else hasGuard = "false"
    ) and
    result =
      "external_call|" + getContractName(contract) + "|" + getFunctionName(func) + "|" + callType +
        "|" + hasGuard + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Detects state modifications (assignments to state variables).
 * Output: state_mod|contract|function|variable|line
 */
string formatStateMod(Solidity::AssignmentExpression assign) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::Identifier id, Solidity::StateVariableDeclaration sv
  |
    assign.getParent+() = func and
    func.getParent+() = contract and
    id.getParent+() = assign.getLeft() and
    sv.getParent+() = contract and
    sv.getName().(Solidity::AstNode).getValue() = id.getValue() and
    result =
      "state_mod|" + getContractName(contract) + "|" + getFunctionName(func) + "|" + id.getValue() +
        "|" + assign.getLocation().getStartLine().toString()
  )
}

/**
 * Potential CEI violation: external call before state modification in same function.
 * Output: cei_violation|contract|function|call_line|state_mod_line|variable
 */
string formatCEIViolation(Solidity::CallExpression call) {
  (
    ExternalCalls::isLowLevelCall(call) or
    ExternalCalls::isContractReferenceCall(call) or
    ExternalCalls::isEtherTransfer(call)
  ) and
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::AssignmentExpression assign, Solidity::Identifier id,
    Solidity::StateVariableDeclaration sv, int callLine, int assignLine
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    assign.getParent+() = func and
    id.getParent+() = assign.getLeft() and
    sv.getParent+() = contract and
    sv.getName().(Solidity::AstNode).getValue() = id.getValue() and
    callLine = call.getLocation().getStartLine() and
    assignLine = assign.getLocation().getStartLine() and
    // External call before state modification
    callLine < assignLine and
    // No reentrancy guard
    not hasReentrancyGuard(func) and
    not hasMutexGuard(func) and
    result =
      "cei_violation|" + getContractName(contract) + "|" + getFunctionName(func) + "|" +
        callLine.toString() + "|" + assignLine.toString() + "|" + id.getValue()
  )
}

/**
 * Function with external calls and state modifications but no guard.
 * Output: unguarded_external|contract|function|call_count|state_mod_count|file:line
 */
string formatUnguardedFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, int extCalls, int stateMods |
    func.getParent+() = contract and
    not hasReentrancyGuard(func) and
    not hasMutexGuard(func) and
    extCalls =
      count(Solidity::CallExpression call |
        call.getParent+() = func and
        (
          ExternalCalls::isLowLevelCall(call) or
          ExternalCalls::isContractReferenceCall(call) or
          ExternalCalls::isEtherTransfer(call)
        )
      ) and
    stateMods =
      count(Solidity::AssignmentExpression assign |
        assign.getParent+() = func and
        exists(
          Solidity::Identifier id, Solidity::StateVariableDeclaration sv
        |
          id.getParent+() = assign.getLeft() and
          sv.getParent+() = contract and
          sv.getName().(Solidity::AstNode).getValue() = id.getValue()
        )
      ) and
    extCalls > 0 and
    stateMods > 0 and
    result =
      "unguarded_external|" + getContractName(contract) + "|" + getFunctionName(func) + "|" +
        extCalls.toString() + "|" + stateMods.toString() + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Detects callback functions (common reentrancy targets).
 * Output: callback|contract|function|file:line
 */
string formatCallback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    (
      funcName.toLowerCase().matches("%callback%") or
      funcName.toLowerCase().matches("%hook%") or
      funcName.toLowerCase().matches("%on%received%") or
      funcName.toLowerCase() = "tokensreceived" or
      funcName.toLowerCase() = "ontokentransfer" or
      funcName.toLowerCase() = "onerc721received" or
      funcName.toLowerCase() = "onerc1155received" or
      funcName.toLowerCase() = "uniswapv2call" or
      funcName.toLowerCase() = "uniswapv3swapcallback" or
      funcName.toLowerCase().matches("%flashloan%")
    ) and
    result =
      "callback|" + getContractName(contract) + "|" + funcName + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

/**
 * Detects receive/fallback functions.
 * Output: eth_receiver|contract|type|file:line
 */
string formatEthReceiver(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcType |
    func.getParent+() = contract and
    (
      getFunctionName(func) = "receive" and funcType = "receive"
      or
      getFunctionName(func) = "fallback" and funcType = "fallback"
    ) and
    result =
      "eth_receiver|" + getContractName(contract) + "|" + funcType + "|" +
        func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
  )
}

// Main query
from string info
where
  info = formatExternalCall(_)
  or
  info = formatStateMod(_)
  or
  info = formatCEIViolation(_)
  or
  info = formatUnguardedFunction(_)
  or
  info = formatCallback(_)
  or
  info = formatEthReceiver(_)
select info, info
