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
 * Output: interface_def|name|function_count|file:line
 */
string formatInterfaceDefinition(Solidity::InterfaceDeclaration iface) {
  exists(int funcCount |
    funcCount = count(Solidity::FunctionDefinition f | f.getParent+() = iface) and
    result =
      "interface_def|" + getInterfaceName(iface) + "|" + funcCount.toString() + "|" +
        iface.getLocation().getFile().getName() + ":" +
        iface.getLocation().getStartLine().toString()
  )
}

/**
 * Interface function.
 * Output: interface_func|interface|function|visibility|file:line
 */
string formatInterfaceFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::InterfaceDeclaration iface |
    func.getParent+() = iface and
    result =
      "interface_func|" + getInterfaceName(iface) + "|" + getFunctionName(func) + "|" +
        getFunctionVisibility(func) + "|" + func.getLocation().getFile().getName() + ":" +
        func.getLocation().getStartLine().toString()
  )
}

/**
 * High-level external call (interface call).
 * Output: high_level_call|caller_contract|caller_func|target|func_called|file:line
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
      "high_level_call|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) +
        "|" + target + "|" + funcCalled + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Low-level external call.
 * Output: low_level_call|caller_contract|caller_func|call_type|file:line
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
      "low_level_call|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) + "|" +
        callType + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Ether transfer (transfer/send).
 * Output: value_transfer|caller_contract|caller_func|transfer_type|file:line
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
      "value_transfer|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) + "|" +
        transferType + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * This.func() external self-call.
 * Output: this_call|contract|caller_func|called_func|file:line
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
      "this_call|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) + "|" +
        calledFunc + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Contract-typed state variable (potential external call target).
 * Output: external_ref|contract|var_name|var_type|file:line
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
      "external_ref|" + getContractName(contract) + "|" + varName + "|" + typeId.getValue() + "|" +
        var.getLocation().getFile().getName() + ":" + var.getLocation().getStartLine().toString()
  )
}

/**
 * Resolved internal call (for call graph completeness).
 * Output: internal_call|caller_contract|caller_func|target_contract|target_func|call_type|file:line
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
      "resolved_call|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) + "|" +
        getContractName(targetContract) + "|" + getFunctionName(targetFunc) + "|" +
        call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
  )
}

/**
 * Unresolved call.
 * Output: unresolved_call|contract|func|target_name|file:line
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
      "unresolved_call|" + getContractName(callerContract) + "|" + getFunctionName(callerFunc) +
        "|" + targetName + "|" + call.getLocation().getFile().getName() + ":" +
        call.getLocation().getStartLine().toString()
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
