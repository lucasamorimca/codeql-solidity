# Data Flow and Taint Tracking

This guide covers SSA form, data flow analysis, and taint tracking for tracking data through Solidity contracts.

## Overview

Data flow tracks how values propagate through code:
- **Local flow**: Within single function (fast)
- **Global flow**: Across functions (thorough but slower)
- **Taint tracking**: Tracks "tainted" data (non-value-preserving)

**Key modules:**
- `codeql.solidity.dataflow.DataFlow` - DataFlow API
- `codeql.solidity.dataflow.TaintTracking` - Taint configuration
- `codeql.solidity.dataflow.internal.SsaImpl` - SSA form

## SSA Form

Static Single Assignment ensures each variable is assigned exactly once, making def-use chains explicit.

### Definition Types

| Type | Description | Example |
|------|-------------|---------|
| `TAssignmentDef` | Assignment expression | `x = 5` |
| `TAugmentedAssignmentDef` | Augmented assignment | `x += 1` |
| `TDeclarationDef` | Variable with initializer | `uint x = 5` |
| `TParameterDef` | Function parameter | `function f(uint x)` |
| `TPhiDef` | Phi node at merge point | Control flow join |

### Tracking Definitions

```ql
import codeql.solidity.dataflow.internal.SsaImpl

from SsaDefinition def
select def, def.getSourceVariable().getName()
```

### Def-Use Chains

```ql
from SsaDefinition def, SsaUse use
where use.getDefinition() = def
select def, "Defined here", use, "Used here"
```

### Phi Nodes

Phi nodes merge definitions at control flow join points.

```ql
from SsaPhiNode phi
select phi, phi.getSourceVariable().getName(), phi.getNumInputs() + " inputs"
```

## DataFlow::Node

Abstracts expressions and parameters as data flow nodes.

```ql
import codeql.solidity.dataflow.DataFlow

from DataFlow::Node node
where node.isMsgSender()
select node, "msg.sender usage"
```

**Key methods:**

| Method | Description |
|--------|-------------|
| `asExpr()` | Underlying expression |
| `asParameter()` | Underlying parameter |
| `isMsgSender()` | Is msg.sender |
| `isMsgValue()` | Is msg.value |
| `isMsgData()` | Is msg.data |
| `isTxOrigin()` | Is tx.origin |
| `isBlockTimestamp()` | Is block.timestamp |

### Solidity-Specific Sources

```ql
/** Gets all user-controlled data sources. */
DataFlow::Node getUserInput() {
  result.isMsgSender() or
  result.isMsgValue() or
  result.isMsgData() or
  result.isTxOrigin() or
  result.isBlockTimestamp() or
  exists(Solidity::Parameter p | result.asParameter() = p)
}
```

## Taint Tracking Configuration

For tracking tainted data across the program.

### Basic Structure

```ql
import codeql.solidity.dataflow.TaintTracking
import codeql.solidity.dataflow.DataFlow

class MyTaintConfig extends TaintTrackingConfiguration {
  MyTaintConfig() { this = "MyTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Define taint sources
  }

  override predicate isSink(DataFlow::Node sink) {
    // Define taint sinks
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Define sanitization points (optional)
  }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Define custom taint propagation (optional)
  }
}
```

### Example: msg.value to External Call

```ql
import codeql.solidity.dataflow.TaintTracking
import codeql.solidity.dataflow.DataFlow
import codeql.solidity.ast.internal.TreeSitter

class MsgValueToCall extends TaintTrackingConfiguration {
  MsgValueToCall() { this = "MsgValueToCall" }

  override predicate isSource(DataFlow::Node source) {
    source.isMsgValue()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Solidity::CallExpression call, Solidity::MemberExpression member |
      member = call.getFunction() and
      member.getProperty().(Solidity::AstNode).getValue() = "call" and
      sink.asExpr() = call.getAnArgument().getAChild*()
    )
  }
}

from MsgValueToCall config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "msg.value flows to external call from $@", source, "here"
```

### Example: Parameter to State Write

```ql
class ParamToStateWrite extends TaintTrackingConfiguration {
  ParamToStateWrite() { this = "ParamToStateWrite" }

  override predicate isSource(DataFlow::Node source) {
    exists(Solidity::Parameter p | source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Solidity::AssignmentExpression assign |
      sink.asExpr() = assign.getRight() and
      exists(Solidity::StateVariableDeclaration sv |
        assign.getLeft().(Solidity::Identifier).getValue() =
          sv.getName().(Solidity::AstNode).getValue()
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // require() validates input
    exists(Solidity::CallExpression req |
      req.getFunction().(Solidity::Identifier).getValue() = "require" and
      node.asExpr() = req.getAnArgument().getAChild*()
    )
  }
}
```

## Sanitizers

Sanitizers stop taint propagation at validation points.

### Common Sanitizers

```ql
override predicate isSanitizer(DataFlow::Node node) {
  // require() statements
  exists(Solidity::CallExpression req |
    req.getFunction().(Solidity::Identifier).getValue() = "require" and
    node.asExpr() = req.getAnArgument().getAChild*()
  )
  or
  // assert() statements
  exists(Solidity::CallExpression asrt |
    asrt.getFunction().(Solidity::Identifier).getValue() = "assert" and
    node.asExpr() = asrt.getAnArgument().getAChild*()
  )
  or
  // Comparison checks
  exists(Solidity::IfStatement ifStmt |
    node.asExpr() = ifStmt.getCondition().getAChild*()
  )
}
```

## Additional Taint Steps

Extend taint propagation through custom operations.

```ql
override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  // Taint through array access
  exists(Solidity::SubscriptExpression sub |
    pred.asExpr() = sub.getIndex() and
    succ.asExpr() = sub
  )
  or
  // Taint through struct field access
  exists(Solidity::MemberExpression member |
    pred.asExpr() = member.getObject() and
    succ.asExpr() = member
  )
  or
  // Taint through keccak256
  exists(Solidity::CallExpression call |
    call.getFunction().(Solidity::Identifier).getValue() = "keccak256" and
    pred.asExpr() = call.getAnArgument().getAChild*() and
    succ.asExpr() = call
  )
}
```

## Path Queries

Track the full path from source to sink.

```ql
/**
 * @name Tainted data flow path
 * @kind path-problem
 * @id solidity/taint-path
 */

import codeql.solidity.dataflow.TaintTracking
import codeql.solidity.dataflow.DataFlow

class MyConfig extends TaintTrackingConfiguration {
  MyConfig() { this = "MyConfig" }
  override predicate isSource(DataFlow::Node source) { source.isMsgSender() }
  override predicate isSink(DataFlow::Node sink) { /* ... */ }
}

from MyConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Tainted data flows from $@ to here", source, "source"
```

## Local vs Global Flow

### Local Flow (Fast)

```ql
/** Holds if data flows locally from source to sink. */
predicate localFlow(DataFlow::Node source, DataFlow::Node sink) {
  // Same function, direct flow
  source.asExpr().getParent+() = sink.asExpr().getParent+()
}
```

### Global Flow (Thorough)

Use `TaintTrackingConfiguration.hasFlow()` for cross-function analysis.

**When to use each:**
- **Local**: Quick checks, same-function patterns
- **Global**: Cross-function, interprocedural tracking

## Performance Tips

1. **Start with local flow** before global
2. **Add sanitizers** to prune search space
3. **Limit sources/sinks** to relevant nodes
4. **Test on small databases** first

```ql
// Good: Specific sources
override predicate isSource(DataFlow::Node source) {
  source.isMsgValue()  // Only msg.value
}

// Bad: Too broad
override predicate isSource(DataFlow::Node source) {
  any()  // Everything is a source
}
```

## Next Steps

- [Call Graph](05-call-graph.md) - Cross-contract calls
- [Security Queries](06-writing-security-queries.md) - Security patterns
- [Advanced Topics](07-advanced-topics.md) - Interprocedural analysis
