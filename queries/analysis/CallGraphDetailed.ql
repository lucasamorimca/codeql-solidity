/**
 * @name Detailed call graph extraction
 * @description Extracts call graph data with separate columns for easy parsing.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/call-graph-detailed
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
 * Detailed query with pipe-separated output for easy CSV conversion.
 * Format: caller_contract|caller_func|target_contract|target_func|call_type|file:line
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
  getContractName(callerContract) + "|" + getFunctionName(callerFunc) + "|" +
    callerFunc.getLocation().getFile().getName() + ":" +
    callerFunc.getLocation().getStartLine().toString() + "|" +
    getContractName(targetContract) + "|" + getFunctionName(targetFunc) + "|" +
    targetFunc.getLocation().getFile().getName() + ":" +
    targetFunc.getLocation().getStartLine().toString() + "|" + callType
