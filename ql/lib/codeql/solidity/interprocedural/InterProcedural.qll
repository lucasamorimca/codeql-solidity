/**
 * Provides a high-level API for inter-procedural analysis in Solidity.
 *
 * This module allows queries to define custom data flow and taint tracking
 * configurations with source, sink, and barrier specifications.
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.dataflow.internal.DataFlowNodes
private import codeql.solidity.dataflow.internal.DataFlowPrivate
private import codeql.solidity.dataflow.internal.DataFlowImpl
private import codeql.solidity.dataflow.internal.TaintImpl
private import codeql.solidity.callgraph.CallResolution
private import codeql.solidity.callgraph.ExternalCalls

/**
 * Module for inter-procedural data flow analysis.
 */
module InterProcedural {
  /**
   * A configuration for inter-procedural data flow analysis.
   *
   * Extend this class to define custom source/sink/barrier specifications.
   */
  abstract class Configuration extends string {
    /** Holds when this configuration applies. */
    bindingset[this]
    Configuration() { any() }

    /**
     * Holds if `node` is a source of potentially problematic data.
     */
    abstract predicate isSource(Node node);

    /**
     * Holds if `node` is a sink where problematic data should not flow.
     */
    abstract predicate isSink(Node node);

    /**
     * Holds if `node` is a barrier that sanitizes data flow.
     *
     * Default implementation: no barriers.
     */
    predicate isBarrier(Node node) { none() }

    /**
     * Holds if there is an additional flow step from `pred` to `succ`.
     *
     * Override this to add custom flow steps for domain-specific patterns.
     */
    predicate isAdditionalFlowStep(Node pred, Node succ) { none() }

    /**
     * Holds if there is an additional taint step from `pred` to `succ`.
     *
     * Override this to add custom taint propagation rules.
     */
    predicate isAdditionalTaintStep(Node pred, Node succ) { none() }

    /**
     * Gets the maximum call depth for inter-procedural analysis.
     *
     * Default is 10. Override for deeper or shallower analysis.
     */
    int getMaxCallDepth() { result = 10 }
  }

  /**
   * Holds if there is data flow from `source` to `sink` according to `config`.
   *
   * This predicate computes flow paths using local flow, jump steps,
   * and any additional flow steps defined in the configuration.
   */
  predicate hasFlow(Configuration config, Node source, Node sink) {
    config.isSource(source) and
    config.isSink(sink) and
    flowsTo(config, source, sink)
  }

  /**
   * Holds if there is taint flow from `source` to `sink` according to `config`.
   *
   * Taint flow includes data flow plus taint propagation through operations.
   */
  predicate hasTaintFlow(Configuration config, Node source, Node sink) {
    config.isSource(source) and
    config.isSink(sink) and
    taintFlowsTo(config, source, sink)
  }

  /**
   * Internal predicate for data flow reachability.
   */
  private predicate flowsTo(Configuration config, Node source, Node sink) {
    source = sink
    or
    not config.isBarrier(sink) and
    exists(Node mid |
      flowStep(config, source, mid) and
      flowsTo(config, mid, sink)
    )
  }

  /**
   * Internal predicate for taint flow reachability.
   */
  private predicate taintFlowsTo(Configuration config, Node source, Node sink) {
    source = sink
    or
    not config.isBarrier(sink) and
    exists(Node mid |
      taintFlowStep(config, source, mid) and
      taintFlowsTo(config, mid, sink)
    )
  }

  /**
   * A single step in data flow.
   */
  private predicate flowStep(Configuration config, Node pred, Node succ) {
    localFlowStep(pred, succ) or
    DataFlowImpl::enhancedJumpStep(pred, succ) or
    config.isAdditionalFlowStep(pred, succ)
  }

  /**
   * A single step in taint flow.
   */
  private predicate taintFlowStep(Configuration config, Node pred, Node succ) {
    flowStep(config, pred, succ) or
    TaintImpl::taintStep(pred, succ) or
    config.isAdditionalTaintStep(pred, succ)
  }

  /**
   * Gets a source node that can reach `sink` according to `config`.
   */
  Node getSourceFor(Configuration config, Node sink) {
    hasFlow(config, result, sink)
  }

  /**
   * Gets a sink node reachable from `source` according to `config`.
   */
  Node getSinkFor(Configuration config, Node source) {
    hasFlow(config, source, result)
  }

  /**
   * Gets a taint source that can reach `sink` according to `config`.
   */
  Node getTaintSourceFor(Configuration config, Node sink) {
    hasTaintFlow(config, result, sink)
  }

  /**
   * Gets a taint sink reachable from `source` according to `config`.
   */
  Node getTaintSinkFor(Configuration config, Node source) {
    hasTaintFlow(config, source, result)
  }
}

/**
 * Pre-built configuration for detecting tainted arithmetic operations.
 */
class TaintedArithmeticConfig extends InterProcedural::Configuration {
  TaintedArithmeticConfig() { this = "TaintedArithmetic" }

  override predicate isSource(Node node) {
    node instanceof TaintImpl::TaintSource
  }

  override predicate isSink(Node node) {
    exists(Solidity::BinaryExpression arith |
      arith.getOperator().(Solidity::AstNode).getValue() in ["+", "-", "*", "/", "%"] and
      (node.asExpr() = arith.getLeft() or node.asExpr() = arith.getRight())
    )
  }
}

/**
 * Pre-built configuration for detecting reentrancy vulnerabilities.
 */
class ReentrancyConfig extends InterProcedural::Configuration {
  ReentrancyConfig() { this = "Reentrancy" }

  override predicate isSource(Node node) {
    // External call is the source of reentrancy risk
    exists(ExternalCalls::ExternalCall call |
      node.asExpr() = call and
      not call.isSelfCall()  // this.func() is not a reentrancy source
    )
  }

  override predicate isSink(Node node) {
    // State write after external call
    exists(Solidity::AssignmentExpression assign |
      node = TPostUpdateNode(assign.getLeft()) and
      isStateVariable(assign.getLeft())
    )
  }

  override predicate isBarrier(Node node) {
    // Reentrancy guard modifier
    exists(Solidity::FunctionDefinition func |
      node.getEnclosingCallable() = func and
      hasReentrancyGuard(func)
    )
  }

  /**
   * Holds if `expr` refers to a state variable.
   */
  private predicate isStateVariable(Solidity::AstNode expr) {
    exists(Solidity::Identifier id, Solidity::StateVariableDeclaration sv |
      id = expr.getAChild*() and
      sv.getName().(Solidity::AstNode).getValue() = id.getValue()
    )
  }

  /**
   * Holds if `func` has a reentrancy guard.
   */
  private predicate hasReentrancyGuard(Solidity::FunctionDefinition func) {
    exists(Solidity::ModifierInvocation inv |
      inv.getParent() = func and
      inv.getAChild*().(Solidity::Identifier).getValue().toLowerCase().matches("%reentr%")
    )
  }
}

/**
 * Pre-built configuration for detecting unprotected selfdestruct.
 */
class UnprotectedSelfdestructConfig extends InterProcedural::Configuration {
  UnprotectedSelfdestructConfig() { this = "UnprotectedSelfdestruct" }

  override predicate isSource(Node node) {
    // Parameter from external function
    node instanceof TaintImpl::ParameterTaintSource
  }

  override predicate isSink(Node node) {
    // Address argument to selfdestruct
    exists(Solidity::CallExpression call |
      call.getFunction().(Solidity::Identifier).getValue() = "selfdestruct" and
      node.asExpr() = call.getChild(0)
    )
  }

  override predicate isBarrier(Node node) {
    // Require check on msg.sender
    exists(
      Solidity::CallExpression req,
      Solidity::BinaryExpression check,
      Solidity::MemberExpression msgSender
    |
      req.getFunction().(Solidity::Identifier).getValue() = "require" and
      check.getParent+() = req and
      msgSender.getParent+() = check and
      msgSender.getObject().(Solidity::Identifier).getValue() = "msg" and
      msgSender.getProperty().(Solidity::AstNode).getValue() = "sender" and
      node.asExpr().getParent+() = check
    )
  }
}

/**
 * Pre-built configuration for detecting tainted delegatecall targets.
 */
class TaintedDelegatecallConfig extends InterProcedural::Configuration {
  TaintedDelegatecallConfig() { this = "TaintedDelegatecall" }

  override predicate isSource(Node node) {
    node instanceof TaintImpl::TaintSource
  }

  override predicate isSink(Node node) {
    // Address used in delegatecall
    exists(ExternalCalls::ExternalCall call |
      call.isDelegateCall() and
      node.asExpr() = call.getTargetAddress()
    )
  }
}

/**
 * Pre-built configuration for detecting unchecked return values.
 */
class UncheckedReturnConfig extends InterProcedural::Configuration {
  UncheckedReturnConfig() { this = "UncheckedReturn" }

  override predicate isSource(Node node) {
    // Result of external call
    exists(ExternalCalls::ExternalCall call |
      node = TCallResultNode(call) and
      call.isLowLevel()
    )
  }

  override predicate isSink(Node node) {
    // Call result not used in require/if
    exists(Solidity::CallExpression call |
      node = TCallResultNode(call) and
      not isResultChecked(call)
    )
  }

  /**
   * Holds if the result of `call` is checked.
   */
  private predicate isResultChecked(Solidity::CallExpression call) {
    // Used in require
    exists(Solidity::CallExpression req |
      req.getFunction().(Solidity::Identifier).getValue() = "require" and
      call.getParent+() = req
    )
    or
    // Used in if condition
    exists(Solidity::IfStatement ifStmt |
      call.getParent+() = ifStmt.getCondition()
    )
    or
    // Assigned and then checked
    exists(Solidity::AssignmentExpression assign |
      assign.getRight() = call
    )
  }
}
