# Call Graph Analysis

This guide covers function call resolution, inheritance analysis, and external call detection for interprocedural queries.

## Overview

Call graph analysis resolves function calls to their targets, essential for:
- Cross-function data flow
- Inheritance-aware analysis
- External call detection

**Key modules:**
- `codeql.solidity.callgraph.CallResolution` - Call target resolution
- `codeql.solidity.callgraph.InheritanceGraph` - Inheritance chains
- `codeql.solidity.callgraph.ExternalCalls` - External call detection

## Call Resolution Types

| Type | Description | Example |
|------|-------------|---------|
| Internal | Same contract | `doSomething()` |
| Inherited | From base contract | `_baseFunction()` |
| Super | Explicit parent | `super.withdraw()` |
| This | External self-call | `this.publicFunc()` |
| Interface | Via typed variable | `token.transfer()` |
| Parameter | Via contract param | `callback.execute()` |

## Using CallResolution

```ql
import codeql.solidity.callgraph.CallResolution

from Solidity::CallExpression call, Solidity::FunctionDefinition target
where CallResolution::resolveCall(call, target)
select call, "Calls $@", target, target.getName().toString()
```

### Resolution Predicates

```ql
// All resolvable calls
CallResolution::resolveCall(call, target)

// Internal calls only
CallResolution::resolveInternalCall(call, target)

// Inherited function calls
CallResolution::resolveInheritedCall(call, target)

// super.func() calls
CallResolution::resolveSuperCall(call, target)

// this.func() calls
CallResolution::resolveThisCall(call, target)

// Interface-typed variable calls
CallResolution::resolveMemberCallToInterface(call, target)

// Parameter-typed calls
CallResolution::resolveMemberCallFromParameter(call, target)
```

### Finding All Callees

```ql
/** Gets functions called by `func`. */
Solidity::FunctionDefinition getCallee(Solidity::FunctionDefinition func) {
  exists(Solidity::CallExpression call |
    call.getParent+() = func and
    CallResolution::resolveCall(call, result)
  )
}

from Solidity::FunctionDefinition func, Solidity::FunctionDefinition callee
where callee = getCallee(func)
select func, "calls", callee
```

### Finding All Callers

```ql
/** Gets functions that call `func`. */
Solidity::FunctionDefinition getCaller(Solidity::FunctionDefinition func) {
  func = getCallee(result)
}
```

### Unresolved Calls

```ql
from Solidity::CallExpression call
where
  CallResolution::isUnresolved(call) and
  not CallResolution::isBuiltinCall(call)
select call, "Unresolved external call"
```

## Inheritance Analysis

### Direct Bases

```ql
import codeql.solidity.callgraph.InheritanceGraph

from Solidity::ContractDeclaration contract, Solidity::ContractDeclaration base
where base = InheritanceGraph::getDirectBase(contract)
select contract, "directly inherits from", base
```

### Transitive Inheritance

```ql
/** Gets all base contracts (transitive). */
Solidity::ContractDeclaration getAllBases(Solidity::ContractDeclaration c) {
  result = InheritanceGraph::getInheritanceChain(c) and
  result != c
}
```

### Inheritance Predicates

```ql
// Direct base contract
InheritanceGraph::getDirectBase(contract)

// All bases (transitive, including self)
InheritanceGraph::getInheritanceChain(contract)

// Holds if contract inherits from base
InheritanceGraph::inheritsFrom(contract, base)

// Inheritance depth
InheritanceGraph::getInheritanceDepth(contract)
```

### Virtual Function Resolution

```ql
/** Gets most derived implementation of function. */
Solidity::FunctionDefinition getMostDerived(
  Solidity::ContractDeclaration contract,
  string funcName
) {
  result = InheritanceGraph::resolveVirtualCall(contract, funcName)
}
```

### Diamond Inheritance

Solidity supports multiple inheritance with C3 linearization.

```ql
from Solidity::ContractDeclaration c
where InheritanceGraph::hasDiamondInheritance(c)
select c, "Has diamond inheritance pattern"
```

```ql
/** Gets function resolved for diamond inheritance. */
Solidity::FunctionDefinition resolveDiamond(
  Solidity::ContractDeclaration contract,
  string funcName
) {
  result = InheritanceGraph::resolveDiamondFunction(contract, funcName)
}
```

### Override Detection

```ql
/** Holds if function overrides a base function. */
predicate isOverride(Solidity::FunctionDefinition func) {
  InheritanceGraph::isOverrideFunction(func)
}

/** Gets the function that `func` overrides. */
Solidity::FunctionDefinition getOverridden(Solidity::FunctionDefinition func) {
  result = InheritanceGraph::getOverriddenFunction(func)
}
```

## External Call Detection

```ql
import codeql.solidity.callgraph.ExternalCalls
```

### Low-Level Calls

```ql
from Solidity::CallExpression call
where ExternalCalls::isLowLevelCall(call)
select call, "Low-level external call"
```

### Call Types

```ql
// .call()
ExternalCalls::isCall(call)

// .delegatecall()
ExternalCalls::isDelegateCall(call)

// .staticcall()
ExternalCalls::isStaticCall(call)

// Any low-level call
ExternalCalls::isLowLevelCall(call)

// High-level contract call
ExternalCalls::isContractReferenceCall(call)

// .transfer() or .send()
ExternalCalls::isEtherTransfer(call)
```

### Finding Dangerous External Calls

```ql
/**
 * @name External call in loop
 * @kind problem
 * @id solidity/external-call-in-loop
 */

import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.controlflow.BasicBlocks

from Solidity::CallExpression call, BasicBlock bb
where
  ExternalCalls::isLowLevelCall(call) and
  bb.getANode() = call and
  exists(BasicBlock pred |
    pred = bb.getAPredecessor() and
    bb.getASuccessor+() = pred  // Back edge = loop
  )
select call, "External call inside loop"
```

## Call Graph Patterns

### Finding Recursive Functions

```ql
from Solidity::FunctionDefinition func
where func = getCallee(func)
select func, "Recursive function"
```

### Finding Entry Points

```ql
/** Holds if function is externally callable and not called internally. */
predicate isEntryPoint(Solidity::FunctionDefinition func) {
  (isPublic(func) or isExternal(func)) and
  not exists(Solidity::FunctionDefinition caller |
    func = getCallee(caller)
  )
}
```

### Call Depth Analysis

```ql
/** Gets maximum call depth from function. */
int getCallDepth(Solidity::FunctionDefinition func) {
  not exists(getCallee(func)) and result = 0
  or
  result = 1 + max(Solidity::FunctionDefinition callee |
    callee = getCallee(func)
  |
    getCallDepth(callee)
  )
}
```

### Cross-Contract Calls

```ql
from
  Solidity::CallExpression call,
  Solidity::FunctionDefinition caller,
  Solidity::ContractDeclaration callerContract
where
  call.getParent+() = caller and
  caller.getParent+() = callerContract and
  (ExternalCalls::isLowLevelCall(call) or
   ExternalCalls::isContractReferenceCall(call))
select call, "Cross-contract call from " + callerContract.getName().toString()
```

## Interprocedural State Analysis

Combine call resolution with state modification detection to find transitive effects:

```ql
/** Holds if `call` is an internal function call (not external). */
private predicate isInternalCall(Solidity::CallExpression call) {
  CallResolution::resolveCall(call, _) and
  not ExternalCalls::isLowLevelCall(call) and
  not ExternalCalls::isContractReferenceCall(call) and
  not ExternalCalls::isEtherTransfer(call) and
  not ExternalCalls::isThisCall(call)
}

/**
 * Transitive state modification via callgraph.
 * QL fixpoint handles mutual recursion automatically.
 */
predicate functionModifiesState(Solidity::FunctionDefinition func,
    Solidity::ContractDeclaration contract, string varName) {
  // Base case
  exists(Solidity::AstNode mod |
    mod.getParent+() = func and directlyModifiesState(mod, contract, varName)
  )
  or
  // Recursive case
  exists(Solidity::CallExpression internalCall, Solidity::FunctionDefinition callee |
    internalCall.getParent+() = func and
    isInternalCall(internalCall) and
    CallResolution::resolveCall(internalCall, callee) and
    functionModifiesState(callee, contract, varName)
  )
}
```

Key points:
- Only follow **internal** calls — external calls can't modify our storage
- `this.func()` is excluded because it's an external call (CALL opcode)
- QL evaluates recursive predicates as a least fixpoint — terminates naturally

See `queries/analysis/ReentrancyPatterns.ql` for the full implementation.

## Library Call Support

Built-in support for common libraries:

```ql
// Check if call is to known library
CallResolution::isKnownLibraryCall(call, libraryName, funcName)

// Libraries supported: SafeMath, Address, SafeERC20, ECDSA, Strings

from Solidity::CallExpression call, string lib, string func
where CallResolution::isKnownLibraryCall(call, lib, func)
select call, lib + "." + func
```

## Performance Tips

1. **Filter by contract first** before resolving calls
2. **Use direct predicates** (resolveInternalCall) when type is known
3. **Cache call graph** in helper predicates
4. **Limit inheritance depth** for performance

```ql
// Good: Filtered resolution
from Solidity::CallExpression call, Solidity::FunctionDefinition target
where
  call.getParent+().(Solidity::ContractDeclaration).getName().toString() = "Token" and
  CallResolution::resolveCall(call, target)
select call, target

// Bad: Unfiltered global resolution
from Solidity::CallExpression call, Solidity::FunctionDefinition target
where CallResolution::resolveCall(call, target)
select call, target
```

## Next Steps

- [Security Queries](06-writing-security-queries.md) - Using call graph for security
- [Advanced Topics](07-advanced-topics.md) - Interprocedural analysis
- [Reference](08-reference.md) - API reference
