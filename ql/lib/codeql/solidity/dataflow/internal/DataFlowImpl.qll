/**
 * Provides enhanced inter-procedural data flow implementation.
 *
 * This module extends the basic data flow with:
 * - Call resolution-based argument-to-parameter flow
 * - Return-to-call-result flow
 * - Modifier argument flow
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Contract
private import codeql.solidity.ast.Function
private import DataFlowNodes
private import DataFlowPrivate
private import codeql.solidity.callgraph.CallResolution
private import codeql.solidity.callgraph.InheritanceGraph
private import codeql.solidity.interprocedural.ModifierAnalysis

/**
 * Module for inter-procedural data flow implementation.
 */
module DataFlowImpl {
  /**
   * Holds if data flows from a call argument to the corresponding parameter
   * using enhanced call resolution.
   *
   * This is an improvement over the basic flow as it uses proper call resolution
   * to track inherited functions, super calls, and member calls.
   */
  predicate argumentToParameterFlow(Node nodeFrom, Node nodeTo) {
    exists(
      Solidity::CallExpression call,
      Solidity::FunctionDefinition target,
      int argIndex,
      Solidity::Parameter param
    |
      // Resolve call to target
      CallResolution::resolveCall(call, target) and
      // From node is argument at index
      nodeFrom = TArgumentNode(call, argIndex) and
      // Get corresponding parameter
      param = getParameterAtIndex(target, argIndex) and
      // To node is the parameter
      nodeTo = TParameterNode(param)
    )
  }

  /**
   * Holds if data flows from a return statement to the call result.
   */
  predicate returnToCallResultFlow(Node nodeFrom, Node nodeTo) {
    exists(
      Solidity::CallExpression call,
      Solidity::FunctionDefinition target,
      Solidity::ReturnStatement ret
    |
      // Resolve call to target
      CallResolution::resolveCall(call, target) and
      // Return statement is in target function
      ret.getParent+() = target and
      // From node is return
      nodeFrom = TReturnNode(ret) and
      // To node is call result
      nodeTo = TCallResultNode(call)
    )
  }

  /**
   * Holds if data flows through a modifier invocation.
   *
   * Arguments passed to a modifier flow to the modifier's parameters.
   */
  predicate modifierArgumentFlow(Node nodeFrom, Node nodeTo) {
    exists(
      Solidity::ModifierInvocation inv,
      Solidity::ModifierDefinition mod,
      int argIndex,
      Solidity::Parameter param
    |
      // Resolve modifier
      ModifierAnalysis::resolveModifier(inv, mod) and
      // Get argument at index (modifier args start at child 1)
      exists(Solidity::AstNode arg |
        arg = inv.getChild(argIndex + 1) and
        nodeFrom.asExpr() = arg
      ) and
      // Get corresponding parameter
      param = getModifierParameterAtIndex(mod, argIndex) and
      // To node is parameter
      nodeTo = TParameterNode(param)
    )
  }

  /**
   * Holds if data flows from a function's modified body back through the modifier.
   *
   * This models the data flow at the placeholder (_) point in a modifier.
   */
  predicate modifierReturnFlow(Node nodeFrom, Node nodeTo) {
    exists(
      Solidity::ModifierInvocation inv,
      Solidity::ModifierDefinition mod,
      Solidity::FunctionDefinition func,
      Solidity::ReturnStatement ret
    |
      // Modifier applied to function
      inv.getParent() = func and
      ModifierAnalysis::resolveModifier(inv, mod) and
      // Return in function body
      ret.getParent+() = func.getBody() and
      nodeFrom = TReturnNode(ret) and
      // Flow to the placeholder continuation in modifier
      // For now, we model this as a pass-through
      nodeTo = nodeFrom
    )
  }

  /**
   * Combined inter-procedural jump step.
   *
   * This is the enhanced version that uses proper call resolution.
   */
  predicate enhancedJumpStep(Node nodeFrom, Node nodeTo) {
    argumentToParameterFlow(nodeFrom, nodeTo) or
    returnToCallResultFlow(nodeFrom, nodeTo) or
    modifierArgumentFlow(nodeFrom, nodeTo)
  }

  /**
   * Gets the parameter at the given index in a function.
   */
  private Solidity::Parameter getParameterAtIndex(Solidity::FunctionDefinition func, int index) {
    exists(int paramCount |
      paramCount = count(Solidity::Parameter p | p.getParent() = func) and
      index >= 0 and
      index < paramCount and
      result = func.getChild(index) and
      result instanceof Solidity::Parameter
    )
  }

  /**
   * Gets the parameter at the given index in a modifier.
   */
  private Solidity::Parameter getModifierParameterAtIndex(
    Solidity::ModifierDefinition mod,
    int index
  ) {
    exists(int paramCount |
      paramCount = count(Solidity::Parameter p | p.getParent() = mod) and
      index >= 0 and
      index < paramCount and
      result = mod.getChild(index) and
      result instanceof Solidity::Parameter
    )
  }

  /**
   * Holds if `source` can flow to `sink` through inter-procedural paths.
   *
   * This is a transitive closure over both local and jump steps.
   */
  predicate interproceduralFlow(Node source, Node sink) {
    source = sink
    or
    exists(Node mid |
      (
        localFlowStep(source, mid) or
        enhancedJumpStep(source, mid)
      ) and
      interproceduralFlow(mid, sink)
    )
  }

  /**
   * Gets all nodes reachable from `source` through inter-procedural flow.
   */
  Node getReachableNode(Node source) {
    interproceduralFlow(source, result)
  }

  /**
   * Holds if there's a flow path from source to sink with a bounded depth.
   *
   * This prevents infinite recursion in complex call graphs.
   */
  predicate boundedFlow(Node source, Node sink, int depth) {
    depth = 0 and source = sink
    or
    depth > 0 and
    depth <= 20 and  // Maximum depth bound
    exists(Node mid |
      (
        localFlowStep(source, mid) or
        enhancedJumpStep(source, mid)
      ) and
      boundedFlow(mid, sink, depth - 1)
    )
  }

  /**
   * Gets the depth of the call stack from `caller` to `callee`.
   *
   * Returns 1 for direct calls, 2 for calls through one intermediate function, etc.
   */
  int getCallDepth(Solidity::FunctionDefinition caller, Solidity::FunctionDefinition callee) {
    // Direct call
    exists(Solidity::CallExpression call |
      call.getParent+() = caller and
      CallResolution::resolveCall(call, callee)
    ) and
    result = 1
    or
    // Indirect call through intermediate function
    exists(Solidity::FunctionDefinition intermediate |
      getCallDepth(caller, intermediate) = result - 1 and
      getCallDepth(intermediate, callee) = 1 and
      result > 1
    )
  }

  /**
   * Holds if `func` is called (directly or transitively) from an external entry point.
   */
  predicate isReachableFromEntry(Solidity::FunctionDefinition func) {
    // Is itself an entry point (public/external)
    isEntryPoint(func)
    or
    // Called from a reachable function
    exists(Solidity::FunctionDefinition caller |
      isReachableFromEntry(caller) and
      getCallDepth(caller, func) >= 1
    )
  }

  /**
   * Holds if `func` is an external entry point (public or external visibility).
   */
  predicate isEntryPoint(Solidity::FunctionDefinition func) {
    exists(Solidity::AstNode visNode, Solidity::AstNode vis |
      visNode.getParent() = func and
      visNode.toString() = "Visibility" and
      vis.getParent() = visNode and
      (vis.getValue() = "external" or vis.getValue() = "public")
    )
  }

  /**
   * Holds if `constructor` is an entry point.
   */
  predicate isConstructorEntryPoint(Solidity::ConstructorDefinition constructor) {
    any()  // All constructors are entry points
  }
}
