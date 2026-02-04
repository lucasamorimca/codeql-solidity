# Writing Security Queries

This guide covers patterns for writing security-focused CodeQL queries targeting common Solidity vulnerabilities.

## Security Query Fundamentals

### Required Metadata

```ql
/**
 * @name Vulnerability name
 * @description Clear explanation of the security issue
 * @kind problem
 * @problem.severity error
 * @precision high
 * @security-severity 8.0
 * @id solidity/vulnerability-id
 * @tags security
 *       external/cwe/cwe-XXX
 */
```

| Field | Values | Description |
|-------|--------|-------------|
| `@problem.severity` | error, warning, recommendation | Issue severity |
| `@precision` | low, medium, high, very-high | False positive rate |
| `@security-severity` | 0.0-10.0 | CVSS-like score |
| `@tags` | security, external/cwe/cwe-XXX | Categories |

### CWE Mapping

| Vulnerability | CWE | Severity |
|--------------|-----|----------|
| Reentrancy | CWE-841 | High |
| Access Control | CWE-284 | High |
| Integer Overflow | CWE-190 | Medium |
| Unchecked Return | CWE-252 | Medium |
| tx.origin Auth | CWE-477 | High |

## Reentrancy Detection (CWE-841)

### Basic Pattern: CEI Violation

```ql
/**
 * @name Reentrancy vulnerability
 * @description External call before state update enables reentrancy
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id solidity/reentrancy
 * @tags security
 *       external/cwe/cwe-841
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls
import codeql.solidity.controlflow.ControlFlowGraph

predicate isStateWrite(Solidity::AssignmentExpression assign) {
  exists(Solidity::StateVariableDeclaration sv |
    assign.getLeft().(Solidity::Identifier).getValue() =
      sv.getName().(Solidity::AstNode).getValue()
  )
}

predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode mod |
    mod.getParent() = func and
    mod.getValue().toLowerCase().matches("%nonreentrant%")
  )
}

from
  Solidity::CallExpression externalCall,
  Solidity::AssignmentExpression stateWrite,
  Solidity::FunctionDefinition func
where
  ExternalCalls::isLowLevelCall(externalCall) and
  isStateWrite(stateWrite) and
  externalCall.getParent+() = func and
  stateWrite.getParent+() = func and
  // External call before state write in CFG
  exists(ControlFlowNode callNode, ControlFlowNode writeNode |
    callNode = externalCall and
    writeNode = stateWrite and
    callNode.getASuccessor+() = writeNode
  ) and
  not hasReentrancyGuard(func)
select externalCall, "External call before state update in $@, potential reentrancy",
  func, func.getName().(Solidity::AstNode).getValue()
```

### Advanced: Cross-Function Reentrancy

```ql
import codeql.solidity.callgraph.CallResolution

predicate callsExternalBeforeStateWrite(Solidity::FunctionDefinition func) {
  exists(Solidity::CallExpression ext, Solidity::AssignmentExpression write |
    ExternalCalls::isLowLevelCall(ext) and
    isStateWrite(write) and
    ext.getParent+() = func and
    write.getParent+() = func and
    exists(ControlFlowNode c, ControlFlowNode w |
      c = ext and w = write and c.getASuccessor+() = w
    )
  )
}

from Solidity::FunctionDefinition caller, Solidity::FunctionDefinition callee
where
  CallResolution::resolveCall(_, callee) and
  callee.getParent+() = caller.getParent+() and
  callsExternalBeforeStateWrite(callee) and
  not hasReentrancyGuard(caller)
select caller, "Calls $@ which has reentrancy pattern", callee, callee.getName().toString()
```

## Access Control (CWE-284)

### Missing Modifier

```ql
/**
 * @name Missing access control
 * @description Public function modifies state without access control
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/missing-access-control
 * @tags security
 *       external/cwe/cwe-284
 */

import codeql.solidity.ast.internal.TreeSitter

predicate isStateModifying(Solidity::FunctionDefinition func) {
  exists(Solidity::AssignmentExpression assign |
    assign.getParent+() = func and
    isStateWrite(assign)
  )
}

predicate hasAccessModifier(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode mod |
    mod.getParent() = func and
    mod.getValue().toLowerCase().matches("%only%")
  )
}

predicate isExternallyCallable(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode vis |
    vis.getParent() = func and
    vis.getValue() in ["public", "external"]
  )
}

from Solidity::FunctionDefinition func
where
  isExternallyCallable(func) and
  isStateModifying(func) and
  not hasAccessModifier(func) and
  not func.getName().(Solidity::AstNode).getValue().toLowerCase().matches("%constructor%")
select func, "Public state-modifying function without access control"
```

### tx.origin Authentication

```ql
/**
 * @name Dangerous tx.origin authentication
 * @description Using tx.origin for authentication is vulnerable to phishing
 * @kind problem
 * @problem.severity error
 * @precision very-high
 * @id solidity/tx-origin-auth
 * @tags security
 *       external/cwe/cwe-477
 */

import codeql.solidity.ast.internal.TreeSitter

from Solidity::BinaryExpression comparison, Solidity::MemberExpression txOrigin
where
  txOrigin = comparison.getAChild*() and
  txOrigin.getObject().(Solidity::Identifier).getValue() = "tx" and
  txOrigin.getProperty().(Solidity::AstNode).getValue() = "origin" and
  comparison.getOperator().(Solidity::AstNode).getValue() in ["==", "!="]
select comparison, "Using tx.origin for authentication is vulnerable to phishing attacks"
```

## Unchecked External Calls (CWE-252)

```ql
/**
 * @name Unchecked low-level call
 * @description Return value of low-level call not checked
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id solidity/unchecked-call
 * @tags security
 *       external/cwe/cwe-252
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.callgraph.ExternalCalls

predicate returnChecked(Solidity::CallExpression call) {
  // In require()
  exists(Solidity::CallExpression req |
    req.getFunction().(Solidity::Identifier).getValue() = "require" and
    call = req.getAnArgument().getAChild*()
  )
  or
  // In if condition
  exists(Solidity::IfStatement ifStmt |
    call = ifStmt.getCondition().getAChild*()
  )
  or
  // Assigned to variable
  exists(Solidity::VariableDeclarationStatement vds |
    call.getParent+() = vds
  )
  or
  // Tuple destructuring
  exists(Solidity::AssignmentExpression assign |
    call = assign.getRight() and
    assign.getLeft().toString().matches("%(%)%")
  )
}

from Solidity::CallExpression call
where
  ExternalCalls::isLowLevelCall(call) and
  not returnChecked(call)
select call, "Return value of low-level call not checked"
```

## Integer Overflow (CWE-190)

```ql
/**
 * @name Potential integer overflow
 * @description Arithmetic without overflow protection in Solidity < 0.8.0
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/integer-overflow
 * @tags security
 *       external/cwe/cwe-190
 */

import codeql.solidity.ast.internal.TreeSitter

predicate isArithmetic(Solidity::BinaryExpression expr, string op) {
  op = expr.getOperator().(Solidity::AstNode).getValue() and
  op in ["+", "-", "*", "**"]
}

predicate inUncheckedBlock(Solidity::AstNode node) {
  exists(Solidity::AstNode unchecked |
    unchecked.toString() = "Unchecked" and
    node.getParent+() = unchecked
  )
}

predicate usesSafeMath(Solidity::BinaryExpression expr) {
  exists(Solidity::CallExpression call, Solidity::MemberExpression member |
    member = call.getFunction() and
    member.getObject().(Solidity::Identifier).getValue() = "SafeMath" and
    expr.getParent+() = call
  )
}

from Solidity::BinaryExpression arith, string op
where
  isArithmetic(arith, op) and
  not inUncheckedBlock(arith) and
  not usesSafeMath(arith)
select arith, "Arithmetic operation (" + op + ") without overflow protection"
```

## Taint-Based Security Query

```ql
/**
 * @name Unvalidated user input to external call
 * @description User-controlled data flows to external call without validation
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id solidity/unvalidated-external-call
 * @tags security
 *       external/cwe/cwe-20
 */

import codeql.solidity.dataflow.TaintTracking
import codeql.solidity.dataflow.DataFlow
import codeql.solidity.callgraph.ExternalCalls

class UserInputToExternalCall extends TaintTrackingConfiguration {
  UserInputToExternalCall() { this = "UserInputToExternalCall" }

  override predicate isSource(DataFlow::Node source) {
    source.isMsgSender() or
    source.isMsgValue() or
    source.isMsgData() or
    exists(Solidity::Parameter p | source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Solidity::CallExpression call |
      ExternalCalls::isLowLevelCall(call) and
      sink.asExpr() = call.getAnArgument().getAChild*()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Solidity::CallExpression req |
      req.getFunction().(Solidity::Identifier).getValue() = "require" and
      node.asExpr() = req.getAnArgument().getAChild*()
    )
  }
}

from UserInputToExternalCall config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, source, sink, "User input flows to external call from $@", source, "here"
```

## Query Template

```ql
/**
 * @name [Vulnerability Name]
 * @description [Clear description of the security issue]
 * @kind problem
 * @problem.severity [error|warning|recommendation]
 * @precision [low|medium|high|very-high]
 * @id solidity/[kebab-case-id]
 * @tags security
 *       external/cwe/cwe-[number]
 */

import codeql.solidity.ast.internal.TreeSitter
// Add other imports as needed

// Helper predicates
predicate helperPredicate(...) {
  // ...
}

from [Variables]
where [Conditions]
select [Location], "[Message]"
```

## Reducing False Positives

1. **Add context checks**: Verify surrounding code patterns
2. **Use sanitizers**: Recognize validation patterns
3. **Check modifiers**: Account for access control
4. **Consider inheritance**: Check base contracts

```ql
// Check for validation before use
predicate isValidated(Solidity::AstNode node, Solidity::FunctionDefinition func) {
  exists(Solidity::CallExpression req, ControlFlowNode reqNode, ControlFlowNode useNode |
    req.getFunction().(Solidity::Identifier).getValue() = "require" and
    node = req.getAnArgument().getAChild*() and
    reqNode = req and
    useNode = node and
    reqNode.getASuccessor*() = useNode
  )
}
```

## Testing Security Queries

1. Create test fixtures with vulnerable and safe patterns
2. Run query and verify detection
3. Check for false positives on safe code
4. Test edge cases

```solidity
// tests/fixtures/ReentrancyTest.sol

// VULNERABLE: CEI violation
contract Vulnerable {
    mapping(address => uint) balances;

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // State update after call
    }
}

// SAFE: Proper CEI
contract Safe {
    mapping(address => uint) balances;

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;  // State update before call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
```

## Next Steps

- [Advanced Topics](07-advanced-topics.md) - Interprocedural security analysis
- [Reference](08-reference.md) - CWE mapping table
