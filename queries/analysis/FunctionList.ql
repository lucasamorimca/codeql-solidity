/**
 * @name Function list with metadata
 * @description Lists all functions with visibility, modifiers, and state access info.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id solidity/function-list
 * @tags analysis
 *       functions
 *       solidity
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.InheritanceGraph

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
  result = "internal"
}

/**
 * Gets mutability (view, pure, payable) of a function.
 */
string getFunctionMutability(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode mut |
    mut.getParent() = func and
    mut.getValue() in ["view", "pure", "payable"] and
    result = mut.getValue()
  )
  or
  not exists(Solidity::AstNode mut |
    mut.getParent() = func and
    mut.getValue() in ["view", "pure", "payable"]
  ) and
  result = "nonpayable"
}

/**
 * Gets modifiers applied to a function as comma-separated string.
 */
string getFunctionModifiers(Solidity::FunctionDefinition func) {
  result =
    concat(Solidity::ModifierInvocation mod |
      mod.getParent() = func
    |
      mod.getValue(), ","
    )
  or
  not exists(Solidity::ModifierInvocation mod | mod.getParent() = func) and
  result = ""
}

/**
 * Holds if function is an entry point (external or public).
 */
predicate isEntryPoint(Solidity::FunctionDefinition func) {
  getFunctionVisibility(func) in ["external", "public"]
}

/**
 * Holds if function is a constructor.
 */
predicate isConstructor(Solidity::FunctionDefinition func) {
  getFunctionName(func) = "constructor"
  or
  exists(Solidity::AstNode node |
    node.getParent() = func and
    node.getValue() = "constructor"
  )
}

/**
 * Holds if function is a fallback or receive function.
 */
predicate isFallbackOrReceive(Solidity::FunctionDefinition func) {
  getFunctionName(func) in ["fallback", "receive"]
  or
  exists(Solidity::AstNode node |
    node.getParent() = func and
    node.getValue() in ["fallback", "receive"]
  )
}

/**
 * Gets parameter count for a function.
 */
int getParameterCount(Solidity::FunctionDefinition func) {
  result = count(Solidity::Parameter p | p.getParent() = func)
}

/**
 * Counts state variable reads in a function.
 */
int getStateReads(Solidity::FunctionDefinition func) {
  result =
    count(Solidity::Identifier id |
      id.getParent+() = func.getBody() and
      exists(Solidity::StateVariableDeclaration sv, Solidity::ContractDeclaration contract |
        func.getParent+() = contract and
        sv.getParent+() = contract and
        sv.getName().(Solidity::AstNode).getValue() = id.getValue()
      )
    )
}

/**
 * Counts state variable writes (assignments) in a function.
 */
int getStateWrites(Solidity::FunctionDefinition func) {
  result =
    count(Solidity::AssignmentExpression assign |
      assign.getParent+() = func.getBody() and
      exists(
        Solidity::Identifier id, Solidity::StateVariableDeclaration sv,
        Solidity::ContractDeclaration contract
      |
        id.getParent+() = assign.getLeft() and
        func.getParent+() = contract and
        sv.getParent+() = contract and
        sv.getName().(Solidity::AstNode).getValue() = id.getValue()
      )
    )
}

/**
 * Main function information.
 * Output: JSON with type, contract, name, visibility, mutability, modifiers, params, state_reads, state_writes, is_entry, is_constructor, file, line
 */
string formatFunction(Solidity::FunctionDefinition func) {
  exists(
    Solidity::ContractDeclaration contract, string visibility, string mutability, string modifiers,
    int params, int reads, int writes, string isEntry, string isCtor
  |
    func.getParent+() = contract and
    visibility = getFunctionVisibility(func) and
    mutability = getFunctionMutability(func) and
    modifiers = getFunctionModifiers(func) and
    params = getParameterCount(func) and
    reads = getStateReads(func) and
    writes = getStateWrites(func) and
    (if isEntryPoint(func) then isEntry = "true" else isEntry = "false") and
    (if isConstructor(func) then isCtor = "true" else isCtor = "false") and
    result =
      "{\"type\":\"function\",\"contract\":\"" + getContractName(contract) + "\",\"name\":\""
        + getFunctionName(func) + "\",\"visibility\":\"" + visibility + "\",\"mutability\":\""
        + mutability + "\",\"modifiers\":\"" + modifiers + "\",\"params\":\"" + params.toString()
        + "\",\"state_reads\":\"" + reads.toString() + "\",\"state_writes\":\""
        + writes.toString() + "\",\"is_entry\":\"" + isEntry + "\",\"is_constructor\":\""
        + isCtor + "\",\"file\":\"" + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

/**
 * Interface function information.
 * Output: JSON with type, interface, name, visibility, mutability, file, line
 */
string formatInterfaceFunction(Solidity::FunctionDefinition func) {
  exists(Solidity::InterfaceDeclaration iface, string visibility, string mutability |
    func.getParent+() = iface and
    visibility = getFunctionVisibility(func) and
    mutability = getFunctionMutability(func) and
    result =
      "{\"type\":\"interface_func\",\"interface\":\"" + iface.getName().(Solidity::AstNode).getValue()
        + "\",\"name\":\"" + getFunctionName(func) + "\",\"visibility\":\"" + visibility
        + "\",\"mutability\":\"" + mutability + "\",\"file\":\""
        + func.getLocation().getFile().getName() + "\",\"line\":\""
        + func.getLocation().getStartLine().toString() + "\"}"
  )
}

// Main query
from string info
where
  info = formatFunction(_)
  or
  info = formatInterfaceFunction(_)
select info, info
