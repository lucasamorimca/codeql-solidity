/**
 * @name Missing access control
 * @description Public/external function modifies state without access control modifier
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/missing-access-control
 * @tags security
 *       external/cwe/cwe-284
 *       access-control
 */

import codeql.solidity.ast.internal.TreeSitter

/**
 * Gets the function name from a function definition.
 */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the contract name from a contract declaration.
 */
string getContractName(Solidity::ContractDeclaration c) {
  result = c.getName().(Solidity::AstNode).getValue()
}

/**
 * Holds if function is public or external.
 */
predicate isExternallyCallable(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.getValue() in ["public", "external"]
  )
}

/**
 * Holds if function modifies state variables.
 */
predicate isStateModifying(Solidity::FunctionDefinition func) {
  exists(Solidity::AssignmentExpression assign, Solidity::StateVariableDeclaration sv |
    assign.getParent+() = func and
    assign.getLeft().(Solidity::Identifier).getValue() =
      sv.getName().(Solidity::AstNode).getValue()
  )
}

/**
 * Holds if function has an access control modifier.
 */
predicate hasAccessModifier(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode mod |
    mod.getParent() = func and
    (
      // Common access control patterns
      mod.getValue().toLowerCase().matches("%only%") or
      mod.getValue().toLowerCase().matches("%auth%") or
      mod.getValue().toLowerCase().matches("%admin%") or
      mod.getValue().toLowerCase().matches("%owner%") or
      mod.getValue().toLowerCase().matches("%role%") or
      mod.getValue().toLowerCase().matches("%access%")
    )
  )
}

/**
 * Holds if function is a constructor.
 */
predicate isConstructor(Solidity::FunctionDefinition func) {
  getFunctionName(func).toLowerCase() = "constructor"
  or
  exists(Solidity::AstNode node |
    node.getParent() = func and
    node.toString() = "Constructor"
  )
}

/**
 * Holds if function is a view or pure function (read-only).
 */
predicate isReadOnly(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode m |
    m.getParent() = func and
    m.getValue() in ["view", "pure"]
  )
}

/**
 * Holds if function has inline access check with require/if.
 */
predicate hasInlineAccessCheck(Solidity::FunctionDefinition func) {
  // Check for require(msg.sender == owner) pattern
  exists(Solidity::CallExpression req, Solidity::BinaryExpression cmp |
    req.getParent+() = func and
    req.getFunction().(Solidity::Identifier).getValue() = "require" and
    cmp = req.getAnArgument().getAChild*() and
    cmp.getOperator().(Solidity::AstNode).getValue() = "==" and
    exists(Solidity::MemberExpression member |
      member = cmp.getAChild*() and
      member.getObject().(Solidity::Identifier).getValue() = "msg" and
      member.getProperty().(Solidity::AstNode).getValue() = "sender"
    )
  )
}

from Solidity::FunctionDefinition func, Solidity::ContractDeclaration contract
where
  func.getParent+() = contract and
  isExternallyCallable(func) and
  isStateModifying(func) and
  not hasAccessModifier(func) and
  not isConstructor(func) and
  not isReadOnly(func) and
  not hasInlineAccessCheck(func)
select func,
  "Function '" + getFunctionName(func) + "' in contract '" + getContractName(contract) +
    "' modifies state without access control"
