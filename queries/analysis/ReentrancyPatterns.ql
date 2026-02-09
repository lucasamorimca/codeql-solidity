/**
 * @name Reentrancy pattern analysis
 * @description Detects CEI violations using control flow reachability instead of line numbers.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/reentrancy-patterns
 * @tags analysis
 *       reentrancy
 *       security
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.controlflow.internal.ControlFlowGraphImpl

/** Gets the contract name. */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/** Gets the function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/** Holds if a function has a reentrancy guard modifier. */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent() = func and
    (
      mod.getValue().toLowerCase().matches("%nonreentrant%") or
      mod.getValue().toLowerCase().matches("%lock%") or
      mod.getValue().toLowerCase().matches("%mutex%") or
      mod.getValue().toLowerCase().matches("%guard%")
    )
  )
}

/** Holds if `assign` writes to a state variable declared in `contract`. */
predicate isStateModification(
  Solidity::AssignmentExpression assign,
  Solidity::ContractDeclaration contract,
  string varName
) {
  exists(Solidity::Identifier id, Solidity::StateVariableDeclaration sv |
    id.getParent+() = assign.getLeft() and
    sv.getParent+() = contract and
    varName = sv.getName().(Solidity::AstNode).getValue() and
    id.getValue() = varName
  )
}

/**
 * Holds if `stateModNode` is reachable from `callNode` via one or more CFG successor edges.
 * Uses CodeQL's built-in transitive closure which handles cycles (loops) correctly
 * and benefits from the evaluator's optimized fixpoint computation.
 */
predicate callReachesStateMod(CfgNode callNode, CfgNode stateModNode) {
  successor+(callNode, stateModNode)
}

/**
 * CEI violation: external call with a state modification reachable via CFG.
 *
 * Uses control flow graph reachability instead of line-number comparison.
 * This correctly handles:
 * - Multi-line statements
 * - Helper function calls between external call and state mod
 * - Non-linear control flow (branches, loops)
 */
string formatCEIViolation(Solidity::CallExpression call) {
  (
    ExternalCalls::isLowLevelCall(call) or
    ExternalCalls::isContractReferenceCall(call) or
    ExternalCalls::isEtherTransfer(call)
  ) and
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::AssignmentExpression assign, string varName
  |
    call.getParent+() = func and
    func.getParent+() = contract and
    assign.getParent+() = func and
    isStateModification(assign, contract, varName) and
    // CFG-based reachability: state mod is reachable from the external call
    callReachesStateMod(call, assign) and
    not hasReentrancyGuard(func) and
    result =
      "cei_violation|" + getContractName(contract) + "|" + getFunctionName(func) + "|" +
        call.getLocation().getStartLine().toString() + "|" +
        assign.getLocation().getStartLine().toString() + "|" + varName
  )
}

/**
 * External call detection.
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
      if hasReentrancyGuard(func)
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
 * State modification detection.
 */
string formatStateMod(Solidity::AssignmentExpression assign) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string varName
  |
    assign.getParent+() = func and
    func.getParent+() = contract and
    isStateModification(assign, contract, varName) and
    result =
      "state_mod|" + getContractName(contract) + "|" + getFunctionName(func) + "|" + varName + "|" +
        assign.getLocation().getStartLine().toString()
  )
}

/**
 * Unguarded function with external calls and state modifications.
 */
string formatUnguardedFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, int extCalls, int stateMods |
    func.getParent+() = contract and
    not hasReentrancyGuard(func) and
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
        isStateModification(assign, contract, _)
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
 * Callback function detection (common reentrancy targets).
 * Only flags external/public functions — private/internal callbacks are not entry points.
 */
string formatCallback(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string funcName |
    func.getParent+() = contract and
    funcName = getFunctionName(func) and
    // Only external/public functions are reentrancy entry points
    exists(Solidity::AstNode vis |
      vis = func.getAChild() and
      vis.toString() in ["external", "public"]
    ) and
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
 * Receive/fallback function detection.
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
