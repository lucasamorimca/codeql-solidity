/**
 * @name Event pattern analysis
 * @description Analyzes event definitions and emissions.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/event-patterns
 * @tags analysis
 *       events
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the contract name.
 */
string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the function name.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Event definition.
 * Output: JSON with type, contract, name, param_count, file, line
 */
string formatEventDefinition(Solidity::EventDefinition event) {
  exists(Solidity::ContractDeclaration contract, int paramCount |
    event.getParent+() = contract and
    paramCount = count(Solidity::EventParameter p | p.getParent() = event) and
    result =
      "{\"type\":\"event_def\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + event.getName().(Solidity::AstNode).getValue() + "\",\"param_count\":\""
        + paramCount.toString() + "\",\"file\":\"" + event.getLocation().getFile().getName()
        + "\",\"line\":\"" + event.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Event emission (emit statement).
 * Output: JSON with type, contract, function, event_name, file, line
 */
string formatEventEmission(Solidity::EmitStatement emit) {
  exists(
    Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract,
    Solidity::CallExpression call, string eventName
  |
    emit.getParent+() = func and
    func.getParent+() = contract and
    call = emit.getAChild() and
    eventName = call.getFunction().(Solidity::Identifier).getValue() and
    result =
      "{\"type\":\"event_emit\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"event_name\":\"" + eventName + "\",\"file\":\""
        + emit.getLocation().getFile().getName() + "\",\"line\":\""
        + emit.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Functions that modify state but don't emit events.
 * Output: JSON with type, contract, function, state_writes, file, line
 */
string formatNoEventFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::ContractDeclaration contract, int stateWrites |
    func.getParent+() = contract and
    // Has state writes
    stateWrites =
      count(Solidity::AssignmentExpression assign |
        assign.getParent+() = func and
        exists(
          Solidity::Identifier id, Solidity::StateVariableDeclaration sv
        |
          id.getParent+() = assign.getLeft() and
          sv.getParent+() = contract and
          sv.getName().(Solidity::AstNode).getValue() = id.getValue()
        )
      ) and
    stateWrites > 0 and
    // But no event emissions
    not exists(Solidity::EmitStatement emit | emit.getParent+() = func) and
    // Is external or public (entry point)
    exists(Solidity::AstNode vis |
      vis.getParent() = func and
      vis.toString() = "Visibility" and
      vis.getAChild().getValue() in ["external", "public"]
    ) and
    result =
      "{\"type\":\"no_event\",\"contract\":\"" + getContractName(contract) + "\",\"function\":\""
        + getFunctionName(func) + "\",\"state_writes\":\"" + stateWrites.toString()
        + "\",\"file\":\"" + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatEventDefinition(_)
  or
  info = formatEventEmission(_)
  or
  info = formatNoEventFunction(_)
select info, info
