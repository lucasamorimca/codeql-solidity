/**
 * @name Debug modifier invocation
 * @kind problem
 * @id solidity/debug-modifier
 */

import codeql.solidity.ast.internal.TreeSitter

from Solidity::FunctionDefinition func, Solidity::ModifierInvocation inv
where inv.getParent() = func
select func.getName().(Solidity::AstNode).getValue() + " has modifier: " + inv.toString(),
  func.getLocation().getFile().getName() + ":" + func.getLocation().getStartLine().toString()
