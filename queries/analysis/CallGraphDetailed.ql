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
 * Detailed query with JSON output.
 * Output: JSON with caller_contract, caller_func, caller_file, caller_line, target_contract, target_func, target_file, target_line, call_type
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
  "{\"caller_contract\":\"" + getContractName(callerContract) + "\",\"caller_func\":\""
    + getFunctionName(callerFunc) + "\",\"caller_file\":\""
    + callerFunc.getLocation().getFile().getName() + "\",\"caller_line\":\""
    + callerFunc.getLocation().getStartLine().toString() + "\",\"target_contract\":\""
    + getContractName(targetContract) + "\",\"target_func\":\"" + getFunctionName(targetFunc)
    + "\",\"target_file\":\"" + targetFunc.getLocation().getFile().getName()
    + "\",\"target_line\":\"" + targetFunc.getLocation().getStartLine().toString()
    + "\",\"call_type\":\"" + callType + "\"}"
