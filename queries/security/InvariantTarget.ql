/**
 * @name Invariant target detection
 * @description Identifies functions suitable for invariant testing with Echidna/Halmos
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/analysis/invariant-target
 * @tags analysis invariant testing solidity
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
 * Holds if `call` is an external call.
 */
private predicate isExternalCall(Solidity::CallExpression call) {
  ExternalCalls::isLowLevelCall(call) or
  ExternalCalls::isContractReferenceCall(call) or
  ExternalCalls::isEtherTransfer(call)
}

/**
 * Holds if a function has an access control modifier.
 */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%onlyowner%") or
    mod.getValue().toLowerCase().matches("%onlyadmin%") or
    mod.getValue().toLowerCase().matches("%onlyrole%") or
    mod.getValue().toLowerCase().matches("%auth%")
  )
}

/**
 * Holds if a function has a reentrancy guard.
 */
predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%nonreentrant%") or
    mod.getValue().toLowerCase().matches("%lock%")
  )
}

/**
 * Holds if a function modifies state.
 */
predicate modifiesState(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode node |
    node.getParent+() = func.getBody() |
    node instanceof Solidity::AssignmentExpression or
    node instanceof Solidity::AugmentedAssignmentExpression or
    node instanceof Solidity::UpdateExpression or
    node instanceof Solidity::UnaryExpression
  )
}

 /**
 * External function suitable for invariant testing
 */
string formatInvariantTarget(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string riskFlags, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    (
      if hasAccessControl(func) then riskFlags = "auth" else riskFlags = "no_auth"
    ) and
    (
      if hasReentrancyGuard(func) then riskFlags = riskFlags + ",reentrancy_guard" else riskFlags = riskFlags + ",no_guard"
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"invariant_target\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"visibility\":\"" + getFunctionVisibility(func) +
      "\",\"risk_flags\":\"" + riskFlags +
      "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * View function that reads state (potential invariant source)
 */
string formatInvariantSource(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public", "view"] and
    exists(Solidity::Identifier id |
      id.getParent+() = func.getBody() and
      exists(Solidity::StateVariableDeclaration sv |
        sv.getParent+() = contract and
        sv.getName().(Solidity::AstNode).getValue() = id.getValue()
      )
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"invariant_source\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"visibility\":\"" + getFunctionVisibility(func) +
      "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * External call without reentrancy guard (high priority for invariant testing)
 */
string formatHighRiskInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    exists(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      isExternalCall(call)
    ) and
    not hasReentrancyGuard(func) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"high_risk_invariant\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"risk\":\"external_call_no_guard\"" +
      ",\"location\":\"" + location + "\"}"
  )
}

/**
 * Balance-modifying function (key for financial invariants)
 */
string formatBalanceInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      getFunctionName(func).toLowerCase().matches("%transfer%") or
      getFunctionName(func).toLowerCase().matches("%withdraw%") or
      getFunctionName(func).toLowerCase().matches("%deposit%") or
      getFunctionName(func).toLowerCase().matches("%mint%") or
      getFunctionName(func).toLowerCase().matches("%burn%") or
      getFunctionName(func).toLowerCase().matches("%send%") or
      getFunctionName(func).toLowerCase().matches("%pay%")
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"balance_invariant\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"operation_type\":\"token_transfer\"" +
      ",\"location\":\"" + location + "\"}"
  )
}

/**
 * Permission-modifying function (key for access control invariants)
 */
string formatPermissionInvariant(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      getFunctionName(func).toLowerCase().matches("%grant%") or
      getFunctionName(func).toLowerCase().matches("%revoke%") or
      getFunctionName(func).toLowerCase().matches("%setowner%") or
      getFunctionName(func).toLowerCase().matches("%addadmin%") or
      getFunctionName(func).toLowerCase().matches("%removeadmin%") or
      getFunctionName(func).toLowerCase().matches("%pause%") or
      getFunctionName(func).toLowerCase().matches("%unpause%")
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"permission_invariant\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"visibility\":\"" + getFunctionVisibility(func) +
      ",\"location\":\"" + location + "\"}"
  )
}

// Main query
from string info
where
  info = formatInvariantTarget(_)
  or
  info = formatInvariantSource(_)
  or
  info = formatHighRiskInvariant(_)
  or
  info = formatBalanceInvariant(_)
  or
  info = formatPermissionInvariant(_)
select info, info
