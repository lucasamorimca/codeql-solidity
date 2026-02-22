/**
 * @name Unresolved calls
 * @description Calls that cannot be statically resolved to a target function.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/unresolved-calls
 * @tags analysis
 *       call-graph
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.CallResolution

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
 * Gets the enclosing function of a call expression.
 */
Solidity::FunctionDefinition getEnclosingFunction(Solidity::CallExpression call) {
  call.getParent+() = result
}

/**
 * Gets the enclosing contract of a function.
 */
Solidity::ContractDeclaration getEnclosingContract(Solidity::FunctionDefinition func) {
  func.getParent+() = result
}

/**
 * Gets a string representation of the call target.
 */
string getCallTargetString(Solidity::CallExpression call) {
  exists(Solidity::Identifier id |
    id = call.getFunction().getAChild*() and
    result = id.getValue()
  )
  or
  exists(Solidity::MemberExpression member |
    member = call.getFunction().getAChild*() and
    result = member.getProperty().(Solidity::AstNode).getValue()
  )
}

/**
 * Unresolved calls (not builtin, not resolvable).
 * Output: JSON with caller, target, file, line
 */
from
  Solidity::CallExpression call,
  Solidity::FunctionDefinition callerFunc,
  Solidity::ContractDeclaration callerContract,
  string targetName
where
  CallResolution::isUnresolved(call) and
  callerFunc = getEnclosingFunction(call) and
  callerContract = getEnclosingContract(callerFunc) and
  targetName = getCallTargetString(call)
select call,
  "{\"caller\":\"" + getContractName(callerContract) + "." + getFunctionName(callerFunc)
    + "\",\"target\":\"[UNRESOLVED: " + targetName + "]\",\"file\":\""
    + call.getLocation().getFile().getName() + "\",\"line\":\""
    + call.getLocation().getStartLine().toString() + "\"}"
