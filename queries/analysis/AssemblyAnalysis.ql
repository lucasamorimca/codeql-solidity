/**
 * @name Assembly block analysis
 * @description Analyzes inline assembly and Yul blocks with security classification.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/assembly-analysis
 * @tags analysis
 *       assembly
 *       yul
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Represents an inline assembly block.
 */
class AssemblyBlock extends Solidity::AssemblyStatement {
  /** Gets the enclosing function. */
  Solidity::FunctionDefinition getEnclosingFunction() { this.getParent+() = result }

  /** Gets the enclosing contract. */
  Solidity::ContractDeclaration getEnclosingContract() { this.getParent+() = result }
}

/**
 * Dangerous operations in assembly with risk levels.
 */
predicate dangerousOperation(string op, string risk) {
  op = "delegatecall" and risk = "critical"
  or
  op = "selfdestruct" and risk = "critical"
  or
  op = "call" and risk = "high"
  or
  op = "create" and risk = "high"
  or
  op = "create2" and risk = "high"
  or
  op = "sstore" and risk = "high"
  or
  op = "staticcall" and risk = "medium"
  or
  op = "sload" and risk = "medium"
  or
  op = "extcodecopy" and risk = "medium"
  or
  op = "codecopy" and risk = "medium"
  or
  op = "mstore" and risk = "low"
  or
  op = "mload" and risk = "low"
  or
  op = "mstore8" and risk = "low"
  or
  op = "returndatacopy" and risk = "low"
  or
  op = "extcodesize" and risk = "low"
}

/**
 * Holds if the assembly block contains a specific operation.
 */
predicate assemblyContainsOp(AssemblyBlock asm, string op) {
  exists(Solidity::AstNode child |
    child.getParent+() = asm and
    (
      child.getValue().toLowerCase() = op
      or
      child.toString().toLowerCase() = op
    )
  )
}

/**
 * Gets the highest risk level from a set of operations.
 */
bindingset[ops]
string getHighestRisk(string ops) {
  (ops.matches("%delegatecall%") or ops.matches("%selfdestruct%")) and result = "critical"
  or
  not (ops.matches("%delegatecall%") or ops.matches("%selfdestruct%")) and
  (
    ops.matches("%call%") or ops.matches("%create%") or ops.matches("%sstore%")
  ) and
  result = "high"
  or
  not (ops.matches("%delegatecall%") or ops.matches("%selfdestruct%")) and
  not (ops.matches("%call%") or ops.matches("%create%") or ops.matches("%sstore%")) and
  (
    ops.matches("%staticcall%") or ops.matches("%sload%") or ops.matches("%extcode%") or
    ops.matches("%codecopy%")
  ) and
  result = "medium"
  or
  not (ops.matches("%delegatecall%") or ops.matches("%selfdestruct%")) and
  not (ops.matches("%call%") or ops.matches("%create%") or ops.matches("%sstore%")) and
  not (
    ops.matches("%staticcall%") or ops.matches("%sload%") or ops.matches("%extcode%") or
    ops.matches("%codecopy%")
  ) and
  result = "low"
}

/**
 * Assembly block information.
 * Output: JSON with type, contract, function, operations, risk_level, file, line
 */
string formatAssemblyBlock(AssemblyBlock asm) {
  exists(
    Solidity::ContractDeclaration contract, Solidity::FunctionDefinition func, string ops,
    string risk
  |
    contract = asm.getEnclosingContract() and
    func = asm.getEnclosingFunction() and
    ops =
      concat(string op |
        dangerousOperation(op, _) and assemblyContainsOp(asm, op)
      |
        op, ","
      ) and
    (
      ops != "" and risk = getHighestRisk(ops)
      or
      ops = "" and risk = "low"
    ) and
    result =
      "{\"type\":\"assembly\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"operations\":\"" + ops + "\",\"risk_level\":\"" + risk
        + "\",\"file\":\"" + asm.getLocation().getFile().getName() + "\",\"line\":\""
        + asm.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Storage operations in assembly.
 * Output: JSON with type, contract, function, operation, file, line
 */
string formatStorageOp(AssemblyBlock asm) {
  exists(Solidity::ContractDeclaration contract, Solidity::FunctionDefinition func, string op |
    contract = asm.getEnclosingContract() and
    func = asm.getEnclosingFunction() and
    op in ["sstore", "sload"] and
    assemblyContainsOp(asm, op) and
    result =
      "{\"type\":\"storage_op\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"operation\":\"" + op + "\",\"file\":\""
        + asm.getLocation().getFile().getName() + "\",\"line\":\""
        + asm.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * External calls in assembly.
 * Output: JSON with type, contract, function, call_type, file, line
 */
string formatAsmExternalCall(AssemblyBlock asm) {
  exists(
    Solidity::ContractDeclaration contract, Solidity::FunctionDefinition func, string callType
  |
    contract = asm.getEnclosingContract() and
    func = asm.getEnclosingFunction() and
    callType in ["call", "delegatecall", "staticcall"] and
    assemblyContainsOp(asm, callType) and
    result =
      "{\"type\":\"asm_call\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"call_type\":\"" + callType + "\",\"file\":\""
        + asm.getLocation().getFile().getName() + "\",\"line\":\""
        + asm.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Critical operations (selfdestruct, delegatecall).
 * Output: JSON with type, contract, function, operation, file, line
 */
string formatCriticalOp(AssemblyBlock asm) {
  exists(Solidity::ContractDeclaration contract, Solidity::FunctionDefinition func, string op |
    contract = asm.getEnclosingContract() and
    func = asm.getEnclosingFunction() and
    op in ["selfdestruct", "delegatecall"] and
    assemblyContainsOp(asm, op) and
    result =
      "{\"type\":\"critical\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"operation\":\"" + op + "\",\"file\":\""
        + asm.getLocation().getFile().getName() + "\",\"line\":\""
        + asm.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Contract creation in assembly.
 * Output: JSON with type, contract, function, create_type, file, line
 */
string formatCreateOp(AssemblyBlock asm) {
  exists(
    Solidity::ContractDeclaration contract, Solidity::FunctionDefinition func, string createType
  |
    contract = asm.getEnclosingContract() and
    func = asm.getEnclosingFunction() and
    createType in ["create", "create2"] and
    assemblyContainsOp(asm, createType) and
    result =
      "{\"type\":\"create\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"create_type\":\"" + createType + "\",\"file\":\""
        + asm.getLocation().getFile().getName() + "\",\"line\":\""
        + asm.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatAssemblyBlock(_)
  or
  info = formatStorageOp(_)
  or
  info = formatAsmExternalCall(_)
  or
  info = formatCriticalOp(_)
  or
  info = formatCreateOp(_)
select info, info
