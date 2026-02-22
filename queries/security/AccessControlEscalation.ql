/**
 * @name Access control escalation detection
 * @description Detects access control escalation patterns: missing auth -> state modification -> external call
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id solidity/security/access-control-escalation
 * @tags security access-control solidity
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
    mod.getValue().toLowerCase().matches("%onlyrole%") or
    mod.getValue().toLowerCase().matches("%auth%") or
    mod.getValue().toLowerCase().matches("%authorized%") or
    mod.getValue().toLowerCase().matches("%ownable%") or
    mod.getValue().toLowerCase().matches("%accesscontrol%") or
    mod.getValue().toLowerCase().matches("%pausable%")
  )
}

/**
 * Holds if a function checks msg.sender in its body.
 */
predicate checksMsgSender(Solidity::FunctionDefinition func) {
  exists(Solidity::MemberExpression m |
    m.getParent+() = func.getBody() |
    m.getObject().(Solidity::Identifier).getValue() = "msg" and
    m.getProperty().(Solidity::AstNode).getValue() = "sender"
  )
}

/**
 * Holds if a function has any access control (modifier or msg.sender check).
 */
predicate hasAccessControlCheck(Solidity::FunctionDefinition func) {
  hasAccessControl(func) or checksMsgSender(func)
}

/**
 * Holds if `node` modifies a state variable.
 */
predicate modifiesState(Solidity::AstNode node) {
  exists(Solidity::AssignmentExpression assign |
    node = assign or
    assign.getParent+() = node.getParent+()
  )
  or
  exists(Solidity::UpdateExpression update |
    node = update or
    update.getParent+() = node.getParent+()
  )
  or
  exists(Solidity::UnaryExpression unary |
    node = unary and
    unary.getOperator().(Solidity::AstNode).getValue() = "delete"
  )
  or
  exists(Solidity::CallExpression call, Solidity::MemberExpression mem |
    node = call and
    call.getFunction() = mem and
    mem.getProperty().(Solidity::AstNode).getValue() in ["push", "pop"]
  )
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
 * Access control escalation pattern: Missing access control + state modification + external call
 */
string formatAccessEscalation(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    exists(Solidity::AstNode node |
      node.getParent+() = func.getBody() and
      modifiesState(node)
    ) and
    exists(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      isExternalCall(call)
    ) and
    getFunctionVisibility(func) in ["external", "public"] and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result = "{\"type\":\"access_escalation\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"vulnerability_chain\":\"no_auth_state_mod_external_call\",\"visibility\":\"" + getFunctionVisibility(func) + "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * Missing access control on sensitive functions
 */
string formatMissingAccessControl(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string sensitivity, string location |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    getFunctionVisibility(func) in ["external", "public"] and
    (
      (
        getFunctionName(func).toLowerCase().matches("%admin%") or
        getFunctionName(func).toLowerCase().matches("%owner%") or
        getFunctionName(func).toLowerCase().matches("%upgrade%") or
        getFunctionName(func).toLowerCase().matches("%set%") or
        getFunctionName(func).toLowerCase().matches("%withdraw%") or
        getFunctionName(func).toLowerCase().matches("%transfer%") or
        getFunctionName(func).toLowerCase().matches("%mint%") or
        getFunctionName(func).toLowerCase().matches("%burn%") or
        getFunctionName(func).toLowerCase().matches("%pause%") or
        getFunctionName(func).toLowerCase().matches("%unpause%") or
        getFunctionName(func).toLowerCase().matches("%grant%") or
        getFunctionName(func).toLowerCase().matches("%revoke%")
      ) and
      sensitivity = "high"
      or
      (
        exists(Solidity::CallExpression call |
          call.getParent+() = func.getBody() and
          isExternalCall(call)
        )
      ) and
      sensitivity = "medium"
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result = "{\"type\":\"missing_access_control\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"severity\":\"" + sensitivity + "\",\"visibility\":\"" + getFunctionVisibility(func) + "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * State-modifying function without access control
 */
string formatUnprotectedStateMod(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    getFunctionVisibility(func) in ["external", "public"] and
    exists(Solidity::AstNode node |
      node.getParent+() = func.getBody() and
      modifiesState(node)
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result = "{\"type\":\"unprotected_state_mod\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"visibility\":\"" + getFunctionVisibility(func) + "\",\"location\":\"" + location + "\"}"
  )
}

/**
 * External call without access control
 */
string formatUnprotectedExternalCall(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, string location |
    func.getParent+() = contract and
    not hasAccessControlCheck(func) and
    getFunctionVisibility(func) in ["external", "public"] and
    exists(Solidity::CallExpression call |
      call.getParent+() = func.getBody() and
      isExternalCall(call)
    ) and
    location = func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString() and
    result = "{\"type\":\"unprotected_external_call\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\"" + getFunctionName(func) + "\",\"visibility\":\"" + getFunctionVisibility(func) + "\",\"location\":\"" + location + "\"}"
  )
}

// Main query
from string info
where
  info = formatAccessEscalation(_)
  or
  info = formatMissingAccessControl(_)
  or
  info = formatUnprotectedStateMod(_)
  or
  info = formatUnprotectedExternalCall(_)
select info, info
