/**
 * @name Delegatecall storage collision detection
 * @description Detects proxy patterns vulnerable to storage collisions due to mismatched variable ordering
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/delegatecall-storage-collision
 * @tags security proxy storage-collision solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls

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
 * Holds if `call` is a delegatecall.
 */
private predicate isDelegatecall(Solidity::CallExpression call) {
  ExternalCalls::isDelegateCall(call)
}

 /**
 * State variable
 */
string formatStateVariable(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string varType, string location |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    varType = var.getType().(Solidity::AstNode).toString() and
    location = var.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"state_var\",\"contract\":\"" + getContractName(contract) +
      "\",\"variable\":\"" + varName +
      "\",\"var_type\":\"" + varType +
      "\",\"line\":" + location + "}"
  )
}

/**
 * Delegatecall detection
 */
string formatDelegatecall(Solidity::CallExpression call) {
  exists(Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract, string location |
    isDelegatecall(call) and
    call.getParent+() = func and
    func.getParent+() = contract and
    location = call.getLocation().getFile().getName() + ":" + call.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"delegatecall\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * Implementation slot detection
 */
string formatImplementationSlot(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string location |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%implementation%") or
      varName.toLowerCase().matches("%logic%") or
      varName.toLowerCase().matches("%target%")
    ) and
    location = var.getLocation().getFile().getName() + ":" + var.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"impl_slot\",\"contract\":\"" + getContractName(contract) +
      "\",\"variable\":\"" + varName +
      "\",\"location\":\"" + location + "\"}"
  )
}

// Main query
from string info
where
  info = formatStateVariable(_)
  or
  info = formatDelegatecall(_)
  or
  info = formatImplementationSlot(_)
select info, info
