/**
 * Provides classes for Static Single Assignment (SSA) form.
 *
 * SSA is a property of an intermediate representation where each variable
 * is assigned exactly once. This simplifies data flow analysis by making
 * def-use chains explicit.
 *
 * For Solidity, we track:
 * - Local variables
 * - Parameters
 * - State variables (with special handling for storage)
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.controlflow.ControlFlowGraph
private import codeql.solidity.controlflow.BasicBlocks
private import codeql.solidity.controlflow.Dominance

/**
 * A variable that can be tracked in SSA form.
 */
class SsaSourceVariable extends Solidity::AstNode {
  SsaSourceVariable() {
    // Local variable declarations
    this instanceof Solidity::VariableDeclaration or
    // Parameters
    this instanceof Solidity::Parameter or
    // State variables
    this instanceof Solidity::StateVariableDeclaration
  }

  /** Gets the name of this variable. */
  string getName() {
    result = this.(Solidity::VariableDeclaration).getName().(Solidity::AstNode).toString()
    or
    result = this.(Solidity::Parameter).getName().(Solidity::AstNode).toString()
    or
    result = this.(Solidity::StateVariableDeclaration).getName().(Solidity::AstNode).toString()
  }

  /** Holds if this is a state variable. */
  predicate isStateVariable() {
    this instanceof Solidity::StateVariableDeclaration
  }

  /** Holds if this is a parameter. */
  predicate isParameter() {
    this instanceof Solidity::Parameter
  }

  /** Holds if this is a local variable. */
  predicate isLocalVariable() {
    this instanceof Solidity::VariableDeclaration and
    not this instanceof Solidity::StateVariableDeclaration
  }
}

/**
 * A definition of an SSA variable.
 *
 * This represents a point where a variable is assigned a value.
 */
newtype TSsaDefinition =
  /** Definition via assignment expression. */
  TAssignmentDef(SsaSourceVariable v, Solidity::AssignmentExpression assign) {
    isAssignmentTo(assign, v)
  } or
  /** Definition via augmented assignment expression (+=, -=, etc.). */
  TAugmentedAssignmentDef(SsaSourceVariable v, Solidity::AugmentedAssignmentExpression aug) {
    isAugmentedAssignmentTo(aug, v)
  } or
  /** Definition via variable declaration with initializer. */
  TDeclarationDef(SsaSourceVariable v, Solidity::VariableDeclarationStatement decl) {
    // The variable declaration is a child of the statement
    v = decl.getAFieldOrChild() and
    v instanceof Solidity::VariableDeclaration and
    exists(decl.getFieldValue())
  } or
  /** Definition via parameter (at function entry). */
  TParameterDef(SsaSourceVariable v, Solidity::FunctionDefinition func) {
    // Parameters are children of the function definition
    v = func.getAFieldOrChild() and
    v instanceof Solidity::Parameter
  } or
  /** Phi node definition at join points. */
  TPhiDef(SsaSourceVariable v, BasicBlock bb) {
    phiNodeNeeded(v, bb)
  }

/**
 * Holds if `assign` is an assignment to variable `v`.
 */
private predicate isAssignmentTo(Solidity::AssignmentExpression assign, SsaSourceVariable v) {
  exists(Solidity::Identifier id |
    id = assign.getLeft() and
    id.toString() = v.getName()
  )
}

/**
 * Holds if `aug` is an augmented assignment to variable `v`.
 */
private predicate isAugmentedAssignmentTo(Solidity::AugmentedAssignmentExpression aug, SsaSourceVariable v) {
  exists(Solidity::Identifier id |
    id = aug.getLeft() and
    id.toString() = v.getName()
  )
}

/**
 * Holds if basic block `bb` contains a definition of variable `v`.
 * This is used for phi node placement without circular dependencies.
 */
private predicate definesVariable(SsaSourceVariable v, BasicBlock bb) {
  exists(Solidity::AssignmentExpression assign |
    isAssignmentTo(assign, v) and
    bb.getANode() = assign
  )
  or
  exists(Solidity::AugmentedAssignmentExpression aug |
    isAugmentedAssignmentTo(aug, v) and
    bb.getANode() = aug
  )
  or
  exists(Solidity::VariableDeclarationStatement decl |
    decl.getAFieldOrChild() = v and
    v instanceof Solidity::VariableDeclaration and
    exists(decl.getFieldValue()) and
    bb.getANode() = decl
  )
  or
  exists(Solidity::FunctionDefinition func |
    func.getAFieldOrChild() = v and
    v instanceof Solidity::Parameter and
    bb.getANode() = func.getBody()
  )
}

/**
 * Holds if a phi node is needed for variable `v` at basic block `bb`.
 *
 * A phi node is needed at a join point if:
 * 1. The block has multiple predecessors (is a join block)
 * 2. At least two predecessors have different reaching definitions for `v`,
 *    OR a definition of `v` can reach `bb` from at least one predecessor
 *    while other paths might have different definitions
 *
 * This uses the dominance frontier concept: a phi is needed where the
 * dominance of a definition ends and control flow merges.
 */
private predicate phiNodeNeeded(SsaSourceVariable v, BasicBlock bb) {
  bb instanceof JoinBasicBlock and
  (
    // Case 1: A definition exists that can reach this join block
    exists(BasicBlock defBlock |
      definesVariable(v, defBlock) and
      defBlock.getASuccessor+() = bb
    )
    or
    // Case 2: Variable is used in or after this block, ensuring we track it
    exists(Solidity::Identifier use |
      use.toString() = v.getName() and
      bb.getASuccessor*().getANode() = use
    )
  ) and
  // Ensure at least two predecessors exist (join block)
  strictcount(bb.getAPredecessor()) >= 2
}

/**
 * Gets an SSA definition that reaches the end of basic block `bb` for variable `v`.
 *
 * For join blocks (multiple predecessors), we use phi nodes to merge definitions.
 * For linear blocks (single predecessor), we propagate the reaching definition.
 */
SsaDefinition reachingDef(SsaSourceVariable v, BasicBlock bb) {
  // Case 1: Non-phi definition in this block - takes precedence
  result.getSourceVariable() = v and
  result.getBasicBlock() = bb and
  not result.isPhi()
  or
  // Case 2: Phi definition in this block (for join blocks)
  result = TPhiDef(v, bb) and
  not definesVariable(v, bb)
  or
  // Case 3: Single predecessor - propagate reaching def
  not definesVariable(v, bb) and
  not phiNodeNeeded(v, bb) and
  exists(BasicBlock pred |
    pred = bb.getUniquePredecessor() and
    result = reachingDef(v, pred)
  )
  or
  // Case 4: Multiple predecessors but no phi needed (variable not live) - pick any predecessor's def
  not definesVariable(v, bb) and
  not phiNodeNeeded(v, bb) and
  not exists(bb.getUniquePredecessor()) and
  exists(BasicBlock pred |
    pred = bb.getAPredecessor() and
    result = reachingDef(v, pred)
  )
}

/**
 * An SSA definition.
 */
class SsaDefinition extends TSsaDefinition {
  /** Gets the source variable being defined. */
  SsaSourceVariable getSourceVariable() {
    this = TAssignmentDef(result, _) or
    this = TAugmentedAssignmentDef(result, _) or
    this = TDeclarationDef(result, _) or
    this = TParameterDef(result, _) or
    this = TPhiDef(result, _)
  }

  /** Gets the basic block containing this definition. */
  BasicBlock getBasicBlock() {
    exists(Solidity::AssignmentExpression assign |
      this = TAssignmentDef(_, assign) and
      result.getANode() = assign
    )
    or
    exists(Solidity::AugmentedAssignmentExpression aug |
      this = TAugmentedAssignmentDef(_, aug) and
      result.getANode() = aug
    )
    or
    exists(Solidity::VariableDeclarationStatement decl |
      this = TDeclarationDef(_, decl) and
      result.getANode() = decl
    )
    or
    exists(Solidity::FunctionDefinition func |
      this = TParameterDef(_, func) and
      // Use the function body's first basic block as the entry
      result.getANode() = func.getBody()
    )
    or
    this = TPhiDef(_, result)
  }

  /** Gets the CFG node of this definition. */
  ControlFlowNode getCfgNode() {
    exists(Solidity::AssignmentExpression assign |
      this = TAssignmentDef(_, assign) and
      result = assign
    )
    or
    exists(Solidity::AugmentedAssignmentExpression aug |
      this = TAugmentedAssignmentDef(_, aug) and
      result = aug
    )
    or
    exists(Solidity::VariableDeclarationStatement decl |
      this = TDeclarationDef(_, decl) and
      result = decl
    )
    or
    exists(Solidity::FunctionDefinition func |
      this = TParameterDef(_, func) and
      result = func
    )
    or
    exists(BasicBlock bb |
      this = TPhiDef(_, bb) and
      result = bb
    )
  }

  /** Gets the value assigned by this definition, if applicable. */
  Solidity::AstNode getValue() {
    exists(Solidity::AssignmentExpression assign |
      this = TAssignmentDef(_, assign) and
      result = assign.getRight()
    )
    or
    exists(Solidity::AugmentedAssignmentExpression aug |
      this = TAugmentedAssignmentDef(_, aug) and
      result = aug.getRight()
    )
    or
    exists(Solidity::VariableDeclarationStatement decl |
      this = TDeclarationDef(_, decl) and
      result = decl.getFieldValue()
    )
  }

  /** Holds if this is a phi definition. */
  predicate isPhi() { this = TPhiDef(_, _) }

  /** Gets a phi input if this is a phi definition. */
  SsaDefinition getAPhiInput() {
    exists(SsaSourceVariable v, BasicBlock bb, BasicBlock pred |
      this = TPhiDef(v, bb) and
      pred = bb.getAPredecessor() and
      result = reachingDef(v, pred)
    )
  }

  /** Gets a use of this definition. */
  SsaUse getAUse() {
    result.getDefinition() = this
  }

  /** Gets the location of this definition. */
  Location getLocation() {
    result = this.getCfgNode().getLocation()
  }

  /** Gets a string representation. */
  string toString() {
    exists(SsaSourceVariable v |
      v = this.getSourceVariable() and
      (
        this = TAssignmentDef(_, _) and result = "SSA def: " + v.getName() + " (assignment)"
        or
        this = TAugmentedAssignmentDef(_, _) and result = "SSA def: " + v.getName() + " (augmented assignment)"
        or
        this = TDeclarationDef(_, _) and result = "SSA def: " + v.getName() + " (declaration)"
        or
        this = TParameterDef(_, _) and result = "SSA def: " + v.getName() + " (parameter)"
        or
        this = TPhiDef(_, _) and result = "SSA def: " + v.getName() + " (phi)"
      )
    )
  }
}

/**
 * A use of an SSA variable.
 */
class SsaUse extends Solidity::Identifier {
  SsaDefinition def;

  SsaUse() {
    exists(SsaSourceVariable v |
      this.toString() = v.getName() and
      def = getReachingDefinition(v, this)
    ) and
    // Not on left side of assignment
    not exists(Solidity::AssignmentExpression assign | assign.getLeft() = this)
  }

  /** Gets the SSA definition that reaches this use. */
  SsaDefinition getDefinition() { result = def }

  /** Gets the source variable being used. */
  SsaSourceVariable getSourceVariable() { result = def.getSourceVariable() }
}

/**
 * Gets the SSA definition that reaches the use at `use` for variable `v`.
 */
private SsaDefinition getReachingDefinition(SsaSourceVariable v, Solidity::Identifier use) {
  exists(BasicBlock bb |
    bb.getANode() = use and
    result = reachingDef(v, bb)
  )
}

/**
 * An SSA phi node.
 */
class SsaPhiNode extends SsaDefinition {
  SsaPhiNode() { this.isPhi() }

  /** Gets an input to this phi node. */
  override SsaDefinition getAPhiInput() {
    result = super.getAPhiInput()
  }

  /** Gets the number of inputs to this phi node. */
  int getNumInputs() {
    result = count(this.getAPhiInput())
  }
}
