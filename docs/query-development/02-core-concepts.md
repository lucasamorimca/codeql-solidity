# Core Concepts: AST and Navigation

This guide covers the Solidity AST hierarchy and navigation patterns for effective query writing.

## AST Overview

CodeQL Solidity uses a tree-sitter generated AST with wrapper classes providing semantic methods.

**Architecture:**
```
Tree-sitter grammar → Solidity::* types (auto-generated) → Wrapper classes (semantic methods)
```

**Key modules:**
- `codeql.solidity.ast.internal.TreeSitter` - Base types
- `codeql.solidity.ast.Contract` - Contract/Interface/Library
- `codeql.solidity.ast.Function` - Functions/Modifiers
- `codeql.solidity.ast.Expr` - Expressions
- `codeql.solidity.ast.Stmt` - Statements

## AST Class Hierarchy

```
AstNode
├── ContractDeclaration
├── InterfaceDeclaration
├── LibraryDeclaration
├── FunctionDefinition
├── ConstructorDefinition
├── ModifierDefinition
├── StateVariableDeclaration
├── Parameter
├── Expression
│   ├── CallExpression
│   ├── MemberExpression
│   ├── BinaryExpression
│   ├── UnaryExpression
│   ├── AssignmentExpression
│   ├── Identifier
│   ├── NumberLiteral
│   └── StringLiteral
└── Statement
    ├── IfStatement
    ├── ForStatement
    ├── WhileStatement
    ├── ReturnStatement
    ├── BlockStatement
    └── AssemblyStatement
```

## Contract Types

### ContractDeclaration

```ql
import codeql.solidity.ast.internal.TreeSitter

from Solidity::ContractDeclaration c
select c, c.getName().(Solidity::AstNode).getValue()
```

**Key methods:**
- `getName()` - Contract name node
- `getAFieldOrChild()` - Any child node
- `getParent()` - Parent node

### Finding Contract Functions

```ql
/** Gets functions defined in a contract. */
Solidity::FunctionDefinition getContractFunction(Solidity::ContractDeclaration c) {
  result.getParent+() = c
}

from Solidity::ContractDeclaration c, Solidity::FunctionDefinition f
where f = getContractFunction(c)
select c, f
```

### Finding State Variables

```ql
from Solidity::ContractDeclaration c, Solidity::StateVariableDeclaration sv
where sv.getParent+() = c
select c, sv.getName().(Solidity::AstNode).getValue()
```

## Function Types

### FunctionDefinition

```ql
/** Gets function visibility. */
string getVisibility(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode v |
    v.getParent() = func and
    v.getValue() in ["public", "private", "internal", "external"] and
    result = v.getValue()
  )
}

/** Holds if function is payable. */
predicate isPayable(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode m |
    m.getParent() = func and
    m.getValue() = "payable"
  )
}
```

### Finding Modifiers

```ql
/** Gets modifiers applied to function. */
Solidity::AstNode getModifier(Solidity::FunctionDefinition func) {
  result.getParent() = func and
  result.toString() = "ModifierInvocation"
}
```

## Expression Types

### CallExpression

```ql
from Solidity::CallExpression call
select call, call.getFunction(), call.getArguments()
```

**Key methods:**
- `getFunction()` - Called function/expression
- `getArguments()` - Arguments node
- `getAnArgument()` - Individual argument (via child navigation)

### MemberExpression

```ql
from Solidity::MemberExpression member
select
  member,
  member.getObject().(Solidity::AstNode).toString(),
  member.getProperty().(Solidity::AstNode).getValue()
```

**Example:** `msg.sender` → object=`msg`, property=`sender`

### BinaryExpression

```ql
from Solidity::BinaryExpression bin
where bin.getOperator().(Solidity::AstNode).getValue() = "+"
select bin, bin.getLeft(), bin.getRight()
```

### AssignmentExpression

```ql
from Solidity::AssignmentExpression assign
select assign, assign.getLeft(), assign.getRight()
```

## Statement Types

### IfStatement

```ql
from Solidity::IfStatement ifStmt
select ifStmt, ifStmt.getCondition(), ifStmt.getConsequence()
```

### ReturnStatement

```ql
from Solidity::ReturnStatement ret
where exists(ret.getExpression())
select ret, ret.getExpression()
```

### BlockStatement

```ql
/** Gets statements in a block. */
Solidity::AstNode getBlockStatement(Solidity::BlockStatement block) {
  result = block.getAFieldOrChild() and
  not result instanceof Solidity::ReservedWord
}
```

## Navigation Patterns

### Parent/Child Navigation

| Method | Description | Example |
|--------|-------------|---------|
| `getParent()` | Direct parent | `node.getParent()` |
| `getParent+()` | Transitive parent | `func.getParent+() = contract` |
| `getChild(int)` | Indexed child | `node.getChild(0)` |
| `getAChild()` | Any child | `node.getAChild()` |
| `getAFieldOrChild()` | Any field or child | `node.getAFieldOrChild()` |

### Finding Enclosing Elements

```ql
/** Gets the contract containing a function. */
Solidity::ContractDeclaration getEnclosingContract(Solidity::FunctionDefinition func) {
  result = func.getParent+()
}

/** Gets the function containing an expression. */
Solidity::FunctionDefinition getEnclosingFunction(Solidity::AstNode node) {
  result = node.getParent+() and
  not exists(Solidity::FunctionDefinition inner |
    inner = node.getParent+() and
    inner != result and
    result = inner.getParent+()
  )
}
```

### Type Refinement

```ql
// Using instanceof
from Solidity::AstNode node
where node instanceof Solidity::CallExpression
select node

// Using type cast
from Solidity::AstNode node, Solidity::CallExpression call
where call = node
select call.getFunction()
```

### Text Extraction

```ql
/** Gets text value of an identifier. */
string getIdentifierValue(Solidity::Identifier id) {
  result = id.getValue()
}

/** Gets function name. */
string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}
```

## Writing Helper Predicates

### Boolean Predicates (is*/has*)

```ql
/** Holds if function is public. */
predicate isPublic(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode v |
    v.getParent() = func and
    v.getValue() = "public"
  )
}

/** Holds if function has a modifier. */
predicate hasModifier(Solidity::FunctionDefinition func, string modName) {
  exists(Solidity::AstNode mod |
    mod.getParent() = func and
    mod.toString() = "ModifierInvocation" and
    mod.getAChild().(Solidity::Identifier).getValue() = modName
  )
}
```

### Getter Predicates (get*)

```ql
/** Gets the return type of a function. */
Solidity::AstNode getReturnType(Solidity::FunctionDefinition func) {
  result = func.getReturnType()
}

/** Gets the visibility of a function. */
string getVisibility(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode v |
    v.getParent() = func and
    v.getValue() in ["public", "private", "internal", "external"] and
    result = v.getValue()
  )
}
```

### Multiple Result Predicates (getA*)

```ql
/** Gets a parameter of the function. */
Solidity::Parameter getAParameter(Solidity::FunctionDefinition func) {
  result.getParent+() = func
}

/** Gets an external call in the function. */
Solidity::CallExpression getAnExternalCall(Solidity::FunctionDefinition func) {
  result.getParent+() = func and
  exists(Solidity::MemberExpression member |
    member = result.getFunction() and
    member.getProperty().(Solidity::AstNode).getValue() in ["call", "delegatecall", "staticcall"]
  )
}
```

## Common Query Patterns

### Find All Contracts

```ql
from Solidity::ContractDeclaration c
select c, c.getName().(Solidity::AstNode).getValue()
```

### Find Functions by Visibility

```ql
from Solidity::FunctionDefinition func
where isPublic(func) or isExternal(func)
select func, "Externally callable function"

predicate isExternal(Solidity::FunctionDefinition func) {
  exists(Solidity::AstNode v |
    v.getParent() = func and
    v.getValue() = "external"
  )
}
```

### Find Calls to Specific Functions

```ql
from Solidity::CallExpression call
where call.getFunction().(Solidity::Identifier).getValue() = "transfer"
select call, "Call to transfer()"
```

### Find State Variable Access

```ql
from Solidity::AssignmentExpression assign, Solidity::StateVariableDeclaration sv
where
  assign.getLeft().(Solidity::Identifier).getValue() =
    sv.getName().(Solidity::AstNode).getValue()
select assign, "Assignment to state variable: " + sv.getName().(Solidity::AstNode).getValue()
```

## Next Steps

- [Control Flow](03-control-flow.md) - CFG analysis
- [Data Flow](04-data-flow.md) - Taint tracking
- [Call Graph](05-call-graph.md) - Function call resolution
