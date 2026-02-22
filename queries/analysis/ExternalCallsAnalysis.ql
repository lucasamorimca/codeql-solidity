/**
 * @name External calls analysis
 * @description Analyzes external call targets and interface definitions.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/external-calls-analysis
 * @tags analysis
 *       external-calls
 *       interfaces
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.callgraph.CallResolution

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the interface name.
 */
string getInterfaceName(Solidity::InterfaceDeclaration iface) {
  result = iface.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets visibility of a function.
 */
string getFunctionVisibility(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility" and
    result = vis.getAChild().getValue()
  )
  or
  not exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.toString() = "Visibility"
  ) and
  result = "public"
}

/**
 * Interface definition.
 */
string formatInterfaceDefinition(Solidity::InterfaceDeclaration iface) {
  exists(int funcCount |
    funcCount = count(Solidity::FunctionDefinition f | f.getParent+() = iface) and
    result =
      "{\"type\":\"interface_def\",\"name\":\"" + getInterfaceName(iface) +
      "\",\"function_count\":" + funcCount.toString() +
      ",\"location\":\"" + iface.getLocation().getFile().getName() + ":" +
        iface.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Interface function.
 */
string formatInterfaceFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::InterfaceDeclaration iface |
    func.getParent+() = iface and
    result =
      "{\"type\":\"interface_func\",\"interface\":\"" + getInterfaceName(iface) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"visibility\":\"" + getFunctionVisibility(func) +
      "\",\"location\":\"" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * High-level external call (interface call).
 */
string formatHighLevelCall(Solidity::CallExpression call) {
  ExternalCalls::isContractReferenceCall(call) and
  exists(
    Solidity::FunctionDefinition callerFunc, Solidity::ContractDeclaration callerContract,
    Solidity::MemberExpression member, string target, string funcCalled
  |
    call.getParent+() = callerFunc and
    callerFunc.getParent+() = callerContract and
    member = call.getFunction().getAChild*() and
    target = member.getObject().(Solidity::AstNode).getAChild*().(Solidity::Identifier).getValue() and
    funcCalled = member.getProperty().(Solidity::AstNode).getValue() and
    result =
      "{\"type\":\"high_level_call\",\"caller_contract\":\"" + getContractName(callerContract) +
      "\",\"caller_function\":\"" + getFunctionName(callerFunc) +
      "\",\"target\":\"" + target +
      "\",\"function_called\":\"" + funcCalled +
      "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Low-level external call.
 */
string formatLowLevelCall(Solidity::CallExpression call) {
  ExternalCalls::isLowLevelCall(call) and
  exists(
    Solidity::FunctionDefinition callerFunc, Solidity::ContractDeclaration callerContract,
    string callType
  |
    call.getParent+() = callerFunc and
    callerFunc.getParent+() = callerContract and
    (
      ExternalCalls::isCall(call) and callType = "call"
      or
      ExternalCalls::isDelegateCall(call) and callType = "delegatecall"
      or
      ExternalCalls::isStaticCall(call) and callType = "staticcall"
    ) and
    result =
      "{\"type\":\"low_level_call\",\"caller_contract\":\"" + getContractName(callerContract) +
      "\",\"caller_function\":\"" + getFunctionName(callerFunc) +
      "\",\"call_type\":\"" + callType +
      "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Ether transfer (transfer/send).
 */
string formatEtherTransfer(Solidity::CallExpression call) {
  ExternalCalls::isEtherTransfer(call) and
  exists(
    Solidity::FunctionDefinition callerFunc, Solidity::ContractDeclaration callerContract,
    Solidity::MemberExpression member, string transferType
  |
    call.getParent+() = callerFunc and
    callerFunc.getParent+() = callerContract and
    member = call.getFunction().getAChild*() and
    transferType = member.getProperty().(Solidity::AstNode).getValue() and
    result =
      "{\"type\":\"value_transfer\",\"caller_contract\":\"" + getContractName(callerContract) +
      "\",\"caller_function\":\"" + getFunctionName(callerFunc) +
      "\",\"transfer_type\":\"" + transferType +
      "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * This.func() external self-call.
 */
string formatThisCall(Solidity::CallExpression call) {
  ExternalCalls::isThisCall(call) and
  not ExternalCalls::isLowLevelCall(call) and
  exists(
    Solidity::FunctionDefinition callerFunc, Solidity::ContractDeclaration callerContract,
    Solidity::MemberExpression member, string calledFunc
  |
    call.getParent+() = callerFunc and
    callerFunc.getParent+() = callerContract and
    member = call.getFunction().getAChild*() and
    calledFunc = member.getProperty().(Solidity::AstNode).getValue() and
    result =
      "{\"type\":\"this_call\",\"contract\":\"" + getContractName(callerContract) +
      "\",\"caller_function\":\"" + getFunctionName(callerFunc) +
      "\",\"called_function\":\"" + calledFunc +
      "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Contract-typed state variable (potential external call target).
 */
string formatExternalReference(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, Solidity::Identifier typeId |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    typeId = var.getType().getAChild*() and
    (
      exists(Solidity::ContractDeclaration targetContract |
        getContractName(targetContract) = typeId.getValue()
      )
      or
      exists(Solidity::InterfaceDeclaration targetIface |
        getInterfaceName(targetIface) = typeId.getValue()
      )
    ) and
    result =
      "{\"type\":\"external_ref\",\"contract\":\"" + getContractName(contract) +
      "\",\"variable_name\":\"" + varName +
      "\",\"variable_type\":\"" + typeId.getValue() +
      "\",\"location\":\"" + var.getLocation().getFile().getName() + ":" +
        var.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Resolved internal call (for call graph completeness).
 */
string formatResolvedCall(Solidity::CallExpression call) {
  exists(
    Solidity::FunctionDefinition callerFunc, Solidity::FunctionDefinition targetFunc,
    Solidity::ContractDeclaration callerContract, Solidity::ContractDeclaration targetContract
  |
    CallResolution::resolveCall(call, targetFunc) and
    call.getParent+() = callerFunc and
    callerFunc.getParent+() = callerContract and
    targetFunc.getParent+() = targetContract and
    result =
      "{\"type\":\"resolved_call\",\"caller_contract\":\"" + getContractName(callerContract) +
      "\",\"caller_function\":\"" + getFunctionName(callerFunc) +
      "\",\"target_contract\":\"" + getContractName(targetContract) +
      "\",\"target_function\":\"" + getFunctionName(targetFunc) +
      "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Unresolved call.
 */
string formatUnresolvedCall(Solidity::CallExpression call) {
  CallResolution::isUnresolved(call) and
  exists(
    Solidity::FunctionDefinition callerFunc, Solidity::ContractDeclaration callerContract,
    string targetName
  |
    call.getParent+() = callerFunc and
    callerFunc.getParent+() = callerContract and
    (
      exists(Solidity::Identifier id |
        id = call.getFunction().getAChild*() and
        targetName = id.getValue()
      )
      or
      exists(Solidity::MemberExpression member |
        member = call.getFunction().getAChild*() and
        targetName = member.getProperty().(Solidity::AstNode).getValue()
      )
    ) and
    result =
      "{\"type\":\"unresolved_call\",\"contract\":\"" + getContractName(callerContract) +
      "\",\"function\":\"" + getFunctionName(callerFunc) +
      "\",\"target_name\":\"" + targetName +
      "\",\"location\":\"" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatInterfaceDefinition(_)
  or
  info = formatInterfaceFunction(_)
  or
  info = formatHighLevelCall(_)
  or
  info = formatLowLevelCall(_)
  or
  info = formatEtherTransfer(_)
  or
  info = formatThisCall(_)
  or
  info = formatExternalReference(_)
  or
  info = formatResolvedCall(_)
  or
  info = formatUnresolvedCall(_)
select info, info
