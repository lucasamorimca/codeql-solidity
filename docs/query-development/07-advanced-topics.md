# Advanced Topics

This guide covers interprocedural analysis, modifier flow, query optimization, and debugging techniques.

## Interprocedural Analysis

Combine call graph with data flow for cross-function tracking.

### Cross-Function Taint Tracking

```ql
import codeql.solidity.dataflow.TaintTracking
import codeql.solidity.dataflow.DataFlow
import codeql.solidity.callgraph.CallResolution

class InterproceduralTaint extends TaintTrackingConfiguration {
  InterproceduralTaint() { this = "InterproceduralTaint" }

  override predicate isSource(DataFlow::Node source) {
    source.isMsgSender()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Solidity::CallExpression call |
      ExternalCalls::isLowLevelCall(call) and
      sink.asExpr() = call.getAnArgument().getAChild*()
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track through function call arguments
    exists(
      Solidity::CallExpression call,
      Solidity::FunctionDefinition callee,
      int i
    |
      CallResolution::resolveCall(call, callee) and
      pred.asExpr() = call.getArgument(i) and
      succ.asParameter() = callee.getParameter(i)
    )
    or
    // Track through return values
    exists(
      Solidity::CallExpression call,
      Solidity::FunctionDefinition callee,
      Solidity::ReturnStatement ret
    |
      CallResolution::resolveCall(call, callee) and
      ret.getParent+() = callee and
      pred.asExpr() = ret.getExpression() and
      succ.asExpr() = call
    )
  }
}
```

### Argument-to-Parameter Flow

```ql
/** Tracks data from call argument to callee parameter. */
predicate argumentToParameter(
  DataFlow::Node argNode,
  DataFlow::Node paramNode,
  Solidity::CallExpression call,
  Solidity::FunctionDefinition callee
) {
  CallResolution::resolveCall(call, callee) and
  exists(int i |
    argNode.asExpr() = call.getArgument(i) and
    paramNode.asParameter() = callee.getParameter(i)
  )
}
```

### Return Value Flow

```ql
/** Tracks data from return statement to call site. */
predicate returnToCallSite(
  DataFlow::Node retNode,
  DataFlow::Node callNode,
  Solidity::FunctionDefinition callee
) {
  exists(Solidity::CallExpression call, Solidity::ReturnStatement ret |
    CallResolution::resolveCall(call, callee) and
    ret.getParent+() = callee and
    retNode.asExpr() = ret.getExpression() and
    callNode.asExpr() = call
  )
}
```

## Modifier Analysis

Track data flow through modifiers.

### Finding Modifier Applications

```ql
import codeql.solidity.interprocedural.ModifierAnalysis

/** Gets modifiers applied to function. */
Solidity::AstNode getAppliedModifier(Solidity::FunctionDefinition func) {
  result.getParent() = func and
  result.toString() = "ModifierInvocation"
}

/** Gets modifier name. */
string getModifierName(Solidity::AstNode mod) {
  result = mod.getAChild().(Solidity::Identifier).getValue()
}
```

### Detecting Guard Modifiers

```ql
/** Holds if function has a guard modifier. */
predicate hasGuard(Solidity::FunctionDefinition func, string guardType) {
  exists(Solidity::AstNode mod |
    mod = getAppliedModifier(func) and
    (
      getModifierName(mod).toLowerCase().matches("%nonreentrant%") and guardType = "reentrancy"
      or
      getModifierName(mod).toLowerCase().matches("%only%") and guardType = "access"
      or
      getModifierName(mod).toLowerCase().matches("%whennotpaused%") and guardType = "pause"
    )
  )
}
```

### Modifier Body Analysis

```ql
/** Gets the modifier definition. */
Solidity::ModifierDefinition getModifierDef(Solidity::AstNode invocation) {
  exists(string name |
    name = getModifierName(invocation) and
    result.getName().(Solidity::AstNode).getValue() = name
  )
}

/** Holds if modifier contains a require statement. */
predicate modifierHasRequire(Solidity::ModifierDefinition mod) {
  exists(Solidity::CallExpression req |
    req.getParent+() = mod and
    req.getFunction().(Solidity::Identifier).getValue() = "require"
  )
}
```

## Query Optimization

### Avoiding Cartesian Products

```ql
// BAD: Unconnected variables create Cartesian product
from Solidity::FunctionDefinition f1, Solidity::FunctionDefinition f2
where f1 != f2
select f1, f2  // All pairs of functions

// GOOD: Variables connected through predicate
from Solidity::FunctionDefinition caller, Solidity::FunctionDefinition callee
where callee = getCallee(caller)
select caller, callee  // Only actual call relationships
```

### Filter Early

```ql
// GOOD: Filter before expensive operations
from Solidity::FunctionDefinition func
where
  func.getName().(Solidity::AstNode).getValue() = "withdraw" and  // Early filter
  exists(getAnExternalCall(func))  // Then check calls
select func

// BAD: Expensive operation before filter
from Solidity::FunctionDefinition func
where
  exists(getAnExternalCall(func)) and  // Checks all functions
  func.getName().(Solidity::AstNode).getValue() = "withdraw"  // Then filters
select func
```

### Use Local Flow First

```ql
/** Prefer local flow when possible. */
predicate localTaintFlow(DataFlow::Node source, DataFlow::Node sink) {
  // Same function scope
  exists(Solidity::FunctionDefinition func |
    source.asExpr().getParent+() = func and
    sink.asExpr().getParent+() = func
  ) and
  // Direct data dependency
  source.asExpr().getAChild*() = sink.asExpr()
  or
  sink.asExpr().getAChild*() = source.asExpr()
}
```

### Strategic Barriers

```ql
class OptimizedConfig extends TaintTrackingConfiguration {
  OptimizedConfig() { this = "OptimizedConfig" }

  override predicate isBarrier(DataFlow::Node node) {
    // Cut off taint at validation points
    exists(Solidity::CallExpression req |
      req.getFunction().(Solidity::Identifier).getValue() = "require" and
      node.asExpr() = req.getAnArgument().getAChild*()
    )
    or
    // Stop at type conversions that sanitize
    exists(Solidity::CallExpression cast |
      cast.getFunction().(Solidity::Identifier).getValue() in ["uint256", "int256", "address"] and
      node.asExpr() = cast
    )
  }
}
```

### Predicate Caching

```ql
/** Cache expensive computations. */
cached
predicate cachedCallGraph(Solidity::FunctionDefinition caller, Solidity::FunctionDefinition callee) {
  exists(Solidity::CallExpression call |
    call.getParent+() = caller and
    CallResolution::resolveCall(call, callee)
  )
}
```

## Debugging Queries

### Quick Eval

In VS Code:
1. Select expression
2. Right-click → "CodeQL: Quick Evaluation"
3. View intermediate results

### Adding Diagnostics

```ql
// Debug: Show all external calls found
from Solidity::CallExpression call
where ExternalCalls::isLowLevelCall(call)
select call, call.getLocation().getStartLine().toString()

// Debug: Show taint sources
from DataFlow::Node source
where source.isMsgSender() or source.isMsgValue()
select source, source.asExpr().getLocation().toString()
```

### Counting Results

```ql
// Count matches to understand query scope
select count(Solidity::FunctionDefinition func | isPublic(func))

// Count by category
from string category, int count
where
  category = "public" and count = count(Solidity::FunctionDefinition f | isPublic(f))
  or
  category = "external" and count = count(Solidity::FunctionDefinition f | isExternal(f))
select category, count
```

### Performance Profiling

```bash
# Run with performance output
codeql query run --evaluator-log=log.json MyQuery.ql --database=db

# Analyze slow predicates
codeql query analyze log.json
```

## Common Mistakes

### 1. Missing Transitive Closure

```ql
// WRONG: Only direct parent
from Solidity::CallExpression call, Solidity::ContractDeclaration c
where call.getParent() = c  // Misses nested calls

// RIGHT: Transitive closure
from Solidity::CallExpression call, Solidity::ContractDeclaration c
where call.getParent+() = c  // Finds all calls in contract
```

### 2. Incorrect String Matching

```ql
// WRONG: Case-sensitive
where func.getName().toString() = "Transfer"

// RIGHT: Case-insensitive when needed
where func.getName().toString().toLowerCase() = "transfer"
```

### 3. Missing Null Checks

```ql
// WRONG: Assumes getName() always returns value
from Solidity::FunctionDefinition func
select func.getName().(Solidity::AstNode).getValue()

// RIGHT: Use exists() for optional values
from Solidity::FunctionDefinition func
where exists(func.getName())
select func.getName().(Solidity::AstNode).getValue()
```

### 4. Unbounded Recursion

```ql
// WRONG: May not terminate
predicate reachable(Node n) {
  reachable(n.getSuccessor())
}

// RIGHT: Use transitive closure operator
predicate reachable(Node start, Node end) {
  end = start.getSuccessor+()
}
```

## Custom Analysis Modules

### Creating a Module

```ql
/**
 * Provides analysis for flash loan detection.
 */
module FlashLoanAnalysis {
  /** Holds if call is a flash loan callback. */
  predicate isFlashLoanCallback(Solidity::FunctionDefinition func) {
    func.getName().(Solidity::AstNode).getValue() in [
      "executeOperation",
      "onFlashLoan",
      "uniswapV2Call",
      "uniswapV3FlashCallback"
    ]
  }

  /** Gets flash loan entry points. */
  Solidity::FunctionDefinition getFlashLoanEntry() {
    isFlashLoanCallback(result)
  }
}
```

### Using Custom Modules

```ql
import FlashLoanAnalysis

from Solidity::FunctionDefinition func
where FlashLoanAnalysis::isFlashLoanCallback(func)
select func, "Flash loan callback function"
```

## Next Steps

- [Reference](08-reference.md) - Complete API reference
- [Examples](examples/) - Working query examples
