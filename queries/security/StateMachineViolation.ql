/**
 * @name State machine violation detection
 * @description Identifies state machine patterns for automatic test generation with Echidna/Halmos
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/analysis/state-machine-violation
 * @tags analysis state-machine testing solidity
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
 * Holds if a function has an access control modifier.
 */
predicate hasAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ModifierInvocation mod |
    mod.getParent*() = func |
    mod.getValue().toLowerCase().matches("%onlyowner%") or
    mod.getValue().toLowerCase().matches("%onlyadmin%") or
    mod.getValue().toLowerCase().matches("%onlyrole%")
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
 * Holds if a function contains a require statement.
 */
predicate hasRequire(Solidity::FunctionDefinition func) {
  exists(Solidity::CallExpression call |
    call.getParent+() = func.getBody() |
    call.getFunction().(Solidity::Identifier).getValue() = "require"
  )
}

 /**
 * State variable used as state indicator (enum-like)
 */
string formatStateIndicator(Solidity::StateVariableDeclaration var) {
  exists(Solidity::ContractDeclaration contract, string varName, string location |
    var.getParent+() = contract and
    varName = var.getName().(Solidity::AstNode).getValue() and
    (
      varName.toLowerCase().matches("%state%") or
      varName.toLowerCase().matches("%status%") or
      varName.toLowerCase().matches("%phase%") or
      varName.toLowerCase().matches("%mode%") or
      varName.toLowerCase().matches("%step%")
    ) and
    location = var.getLocation().getFile().getName() + ":" + var.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"state_indicator\",\"contract\":\"" + getContractName(contract) +
      "\",\"variable\":\"" + varName +
      "\",\"var_type\":\"" + var.getType().(Solidity::AstNode).toString() +
      "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * State transition function (modifies state)
 */
string formatStateTransition(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string hasAccess, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    (
      if hasAccessControl(func) then hasAccess = "true" else hasAccess = "false"
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"state_transition\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"has_access_control\":" + hasAccess +
      ",\"location\":\"" + location + "\"}"
  )
}

/**
 * Function with state-dependent access control
 */
string formatStateDependentAccess(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    hasRequire(func) and
    modifiesState(func) and
    not hasAccessControl(func) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"state_dependent_access\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      "\",\"has_require\":true,\"location\":\"" + location + "\"}"
  )
}

/**
 * Multiple state variables that should maintain invariants
 */
string formatStateInvariantGroup(Solidity::ContractDeclaration contract) {
  exists(int varCount, string location |
    varCount = count(Solidity::StateVariableDeclaration v |
      v.getParent+() = contract and
      (
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%state%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%status%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%balance%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%total%") or
        v.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%supply%")
      )
    ) and
    varCount > 1 and
    location = contract.getLocation().getFile().getName() + ":" + contract.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"state_invariant_group\",\"contract\":\"" + getContractName(contract) +
      "\",\"variable_count\":" + varCount.toString() +
      ",\"location\":\"" + location + "\"}"
  )
}

/**
 * Unguarded state transition (potential vulnerability)
 */
string formatUnguardedStateTransition(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    getFunctionVisibility(func) in ["external", "public"] and
    modifiesState(func) and
    not hasAccessControl(func) and
    not hasRequire(func) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result =
      "{\"type\":\"unguarded_state_transition\",\"contract\":\"" + getContractName(contract) +
      "\",\"function\":\"" + getFunctionName(func) +
      ",\"location\":\"" + location + "\"}"
  )
}

// Main query
from string info
where
  info = formatStateIndicator(_)
  or
  info = formatStateTransition(_)
  or
  info = formatStateDependentAccess(_)
  or
  info = formatStateInvariantGroup(_)
  or
  info = formatUnguardedStateTransition(_)
select info, info
