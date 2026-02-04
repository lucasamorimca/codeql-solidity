/**
 * @name Reentrancy vulnerability
 * @description Detects external calls before state updates (CEI violation)
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id solidity/reentrancy
 * @tags security
 *       external/cwe/cwe-841
 *       reentrancy
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.controlflow.ControlFlowGraph

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Holds if `assign` writes to a state variable.
 */
predicate isStateWrite(Solidity::AssignmentExpression assign) {
  exists(Solidity::StateVariableDeclaration sv |
    assign.getLeft().(Solidity::Identifier).getValue() =
      sv.getName().(Solidity::AstNode).getValue()
  )
}

/**
 * Holds if function has a reentrancy guard modifier.
 */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode mod |
    mod.getParent() = func and
    mod.getValue().toLowerCase().matches("%nonreentrant%")
  )
  or
  exists(Solidity::AstNode mod |
    mod.getParent() = func and
    mod.getValue().toLowerCase().matches("%mutex%")
  )
}

/**
 * Holds if function has a mutex/lock pattern.
 */
predicate hasMutexPattern(Solidity::FunctionDefinition func) {
  exists(Solidity::AssignmentExpression lockSet, Solidity::AssignmentExpression lockUnset |
    lockSet.getParent+() = func and
    lockUnset.getParent+() = func and
    lockSet.getLeft().(Solidity::Identifier).getValue().toLowerCase().matches("%lock%") and
    lockUnset.getLeft().(Solidity::Identifier).getValue().toLowerCase().matches("%lock%")
  )
}

from
  Solidity::CallExpression externalCall,
  Solidity::AssignmentExpression stateWrite,
  Solidity::FunctionDefinition func
where
  // External call (low-level or ether transfer)
  (ExternalCalls::isLowLevelCall(externalCall) or ExternalCalls::isEtherTransfer(externalCall)) and
  // State write
  isStateWrite(stateWrite) and
  // Both in same function
  externalCall.getParent+() = func and
  stateWrite.getParent+() = func and
  // External call comes before state write in CFG (CEI violation)
  exists(ControlFlowNode callNode, ControlFlowNode writeNode |
    callNode = externalCall and
    writeNode = stateWrite and
    callNode.getASuccessor+() = writeNode
  ) and
  // No reentrancy protection
  not hasReentrancyGuard(func) and
  not hasMutexPattern(func)
select externalCall,
  "External call before state update in function '" + getFunctionName(func) +
    "', potential reentrancy vulnerability"
