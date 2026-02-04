/**
 * @name Call graph extraction
 * @description Extracts call graph data showing caller to callee relationships.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/call-graph
 * @tags analysis
 *       call-graph
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.CallResolution
import codeql.solidity.callgraph.ExternalCalls

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
 * Gets the enclosing contract of a function.
 */
Solidity::ContractDeclaration getEnclosingContract(Solidity::FunctionDefinition func) {
  func.getParent+() = result
}

/**
 * Gets the enclosing function of a call expression.
 */
Solidity::FunctionDefinition getEnclosingFunction(Solidity::CallExpression call) {
  call.getParent+() = result
}

/**
 * Gets the call type as a string.
 */
string getCallType(Solidity::CallExpression call, Solidity::FunctionDefinition target) {
  CallResolution::resolveInternalCall(call, target) and result = "internal"
  or
  CallResolution::resolveInheritedCall(call, target) and result = "inherited"
  or
  CallResolution::resolveSuperCall(call, target) and result = "super"
  or
  CallResolution::resolveThisCall(call, target) and result = "this"
  or
  CallResolution::resolveMemberCallToInterface(call, target) and result = "interface"
  or
  CallResolution::resolveMemberCallFromParameter(call, target) and result = "parameter"
}

/**
 * Formats the target info based on call type.
 * For inherited/super calls, explicitly shows "inherited from BaseContract".
 */
bindingset[callType]
string formatTarget(
  Solidity::FunctionDefinition targetFunc,
  Solidity::ContractDeclaration targetContract,
  string callType
) {
  // For inherited or super calls, show "inherited from BaseContract"
  (callType = "inherited" or callType = "super") and
  result =
    getFunctionName(targetFunc) + " (inherited from " + getContractName(targetContract) + " at " +
      targetFunc.getLocation().getFile().getName() + ":" +
      targetFunc.getLocation().getStartLine().toString() + ")"
  or
  // For other calls, show standard format
  not (callType = "inherited" or callType = "super") and
  result =
    getContractName(targetContract) + "." + getFunctionName(targetFunc) + " (" +
      targetFunc.getLocation().getFile().getName() + ":" +
      targetFunc.getLocation().getStartLine().toString() + ")"
}

/**
 * Main query: resolved calls with full context.
 * Output format: callerContract.callerFunc -> targetContract.targetFunc (callType)
 */
from
  Solidity::CallExpression call,
  Solidity::FunctionDefinition callerFunc,
  Solidity::FunctionDefinition targetFunc,
  Solidity::ContractDeclaration callerContract,
  Solidity::ContractDeclaration targetContract,
  string callType
where
  CallResolution::resolveCall(call, targetFunc) and
  callerFunc = getEnclosingFunction(call) and
  callerContract = getEnclosingContract(callerFunc) and
  targetContract = getEnclosingContract(targetFunc) and
  callType = getCallType(call, targetFunc)
select call,
  getContractName(callerContract) + "." + getFunctionName(callerFunc) + " (" +
    callerFunc.getLocation().getFile().getName() + ":" +
    callerFunc.getLocation().getStartLine().toString() + ") -> " +
    formatTarget(targetFunc, targetContract, callType) + " [" + callType + "]"
