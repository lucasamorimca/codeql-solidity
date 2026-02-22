/**
 * @name External call graph extraction
 * @description Extracts external calls (low-level, delegate, interface calls).
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/external-call-graph
 * @tags analysis
 *       call-graph
 *       external-calls
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
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
 * Gets the external call type.
 */
string getExternalCallType(ExternalCalls::ExternalCall call) {
  ExternalCalls::isCall(call) and result = "call"
  or
  ExternalCalls::isDelegateCall(call) and result = "delegatecall"
  or
  ExternalCalls::isStaticCall(call) and result = "staticcall"
  or
  ExternalCalls::isThisCall(call) and not ExternalCalls::isLowLevelCall(call) and result = "this"
  or
  ExternalCalls::isContractReferenceCall(call) and result = "interface"
  or
  ExternalCalls::isEtherTransfer(call) and result = "transfer"
}

/**
 * External calls query.
 * Output: JSON with caller, call_type, file, line
 */
from
  ExternalCalls::ExternalCall call,
  Solidity::FunctionDefinition callerFunc,
  Solidity::ContractDeclaration callerContract,
  string callType
where
  callerFunc = call.getEnclosingFunction() and
  callerContract = call.getEnclosingContract() and
  callType = getExternalCallType(call)
select call,
  "{\"caller\":\"" + getContractName(callerContract) + "." + getFunctionName(callerFunc)
    + "\",\"call_type\":\"" + callType + "\",\"file\":\""
    + call.getLocation().getFile().getName() + "\",\"line\":\""
    + call.getLocation().getStartLine().toString() + "\"}"
