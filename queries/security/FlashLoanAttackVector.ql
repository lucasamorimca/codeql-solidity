/**
 * @name Flash loan attack vector detection
 * @description Detects flash loan + governance attack vectors where governance can be manipulated via ERC20 callbacks
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/flash-loan-attack-vector
 * @tags security flash-loan governance solidity
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
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the visibility of a function.
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
 * Holds if a function has access control.
 */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%onlyowner%") or
    mod.getValue().toLowerCase().matches("%onlyadmin%") or
    mod.getValue().toLowerCase().matches("%onlyrole%") or
    mod.getValue().toLowerCase().matches("%auth%") or
    mod.getValue().toLowerCase().matches("%authorized%") or
    mod.getValue().toLowerCase().matches("%ownable%") or
    mod.getValue().toLowerCase().matches("%accesscontrol%")
  )
}

/**
 * Holds if `func` is a governance function (vote, delegate, propose, etc.)
 */
predicate isGovernanceFunction(Solidity::FunctionDefinition func) {
  exists(string funcName |
    funcName = getFunctionName(func).toLowerCase() |
    funcName.matches("%vote%") or
    funcName.matches("%delegate%") or
    funcName.matches("%propose%") or
    funcName.matches("%execute%") or
    funcName.matches("%queue%") or
    funcName.matches("%cast%") or
    funcName.matches("%submit%") or
    funcName.matches("%mint%") or
    funcName.matches("%burn%") and
    not funcName.matches("%nft%")
  )
}

 /**
 * Flash loan attack vector: governance functions that can be called directly (no access control)
 */
string formatFlashLoanVector(Solidity::FunctionDefinition govFunc) {
  exists(Solidity::ContractDeclaration contract, string location |
    govFunc.getParent+() = contract and
    isGovernanceFunction(govFunc) and
    not hasAccessControl(govFunc) and
    getFunctionVisibility(govFunc) in ["external", "public"] and
    location = govFunc.getLocation().getFile().getName() + ":" + govFunc.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"flash_loan_vector\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(govFunc) +
      "\",\"entry_point\":\"direct\",\"has_access_control\":false" +
      ",\"location\":\"" + location + "\"}"
  )
}

/**
 * Governance function without access control
 */
string formatGovernanceNoAuth(Solidity::FunctionDefinition govFunc) {
  exists(Solidity::ContractDeclaration contract, string location |
    govFunc.getParent+() = contract and
    isGovernanceFunction(govFunc) and
    not hasAccessControl(govFunc) and
    getFunctionVisibility(govFunc) in ["external", "public"] and
    location = govFunc.getLocation().getFile().getName() + ":" + govFunc.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"governance_no_auth\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(govFunc) +
      "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * Token balance manipulation opportunity: governance uses token balance for decisions
 */
string formatTokenBalanceGovernance(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    isGovernanceFunction(func) and
    exists(Solidity::MemberExpression mem |
      mem.getParent+() = func.getBody() |
      mem.getObject().(Solidity::Identifier).getValue() = "balanceOf" or
      mem.getObject().(Solidity::Identifier).getValue() = "balance"
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"token_balance_governance\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"decision_type\":\"balance_check\",\"location\":\"" + location + "\"}"
  )
}

// Main query
from string info
where
  info = formatFlashLoanVector(_)
  or
  info = formatGovernanceNoAuth(_)
  or
  info = formatTokenBalanceGovernance(_)
select info, info
