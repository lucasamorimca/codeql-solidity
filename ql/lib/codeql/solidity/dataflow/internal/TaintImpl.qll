/**
 * Provides taint tracking implementation for Solidity.
 *
 * This module defines:
 * - Taint sources (user input, external call results, etc.)
 * - Taint sinks (security-sensitive operations)
 * - Taint propagation rules
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Contract
private import codeql.solidity.ast.Function
private import DataFlowNodes
private import DataFlowPrivate
private import codeql.solidity.callgraph.ExternalCalls

/**
 * Module for taint tracking implementation.
 */
module TaintImpl {
  /**
   * A taint source - a node that introduces potentially untrusted data.
   */
  abstract class TaintSource extends Node {
    /** Gets a description of this taint source type. */
    abstract string getSourceType();
  }

  /**
   * A taint sink - a security-sensitive operation.
   */
  abstract class TaintSink extends Node {
    /** Gets a description of this taint sink type. */
    abstract string getSinkType();
  }

  /**
   * A taint barrier - a node that sanitizes tainted data.
   */
  abstract class TaintBarrier extends Node {
    /** Gets a description of why this node is a barrier. */
    abstract string getBarrierReason();
  }

  /**
   * Taint source: msg.sender, msg.value, msg.data
   */
  class MsgTaintSource extends TaintSource {
    MsgTaintSource() {
      exists(Solidity::MemberExpression member |
        this.asExpr() = member and
        member.getObject().(Solidity::Identifier).getValue() = "msg" and
        member.getProperty().(Solidity::AstNode).getValue() in ["sender", "value", "data", "sig"]
      )
    }

    override string getSourceType() {
      exists(Solidity::MemberExpression member |
        this.asExpr() = member and
        result = "msg." + member.getProperty().(Solidity::AstNode).getValue()
      )
    }
  }

  /**
   * Taint source: tx.origin, tx.gasprice
   */
  class TxTaintSource extends TaintSource {
    TxTaintSource() {
      exists(Solidity::MemberExpression member |
        this.asExpr() = member and
        member.getObject().(Solidity::Identifier).getValue() = "tx" and
        member.getProperty().(Solidity::AstNode).getValue() in ["origin", "gasprice"]
      )
    }

    override string getSourceType() {
      exists(Solidity::MemberExpression member |
        this.asExpr() = member and
        result = "tx." + member.getProperty().(Solidity::AstNode).getValue()
      )
    }
  }

  /**
   * Taint source: block.timestamp, block.number, etc.
   */
  class BlockTaintSource extends TaintSource {
    BlockTaintSource() {
      exists(Solidity::MemberExpression member |
        this.asExpr() = member and
        member.getObject().(Solidity::Identifier).getValue() = "block" and
        member.getProperty().(Solidity::AstNode).getValue() in [
          "timestamp", "number", "difficulty", "gaslimit", "coinbase", "basefee", "chainid"
        ]
      )
    }

    override string getSourceType() {
      exists(Solidity::MemberExpression member |
        this.asExpr() = member and
        result = "block." + member.getProperty().(Solidity::AstNode).getValue()
      )
    }
  }

  /**
   * Taint source: External call results.
   */
  class ExternalCallTaintSource extends TaintSource {
    ExternalCalls::ExternalCall call;

    ExternalCallTaintSource() {
      this = TCallResultNode(call)
    }

    override string getSourceType() {
      if call.isLowLevel()
      then result = "low-level external call result"
      else result = "external call result"
    }

    /** Gets the external call. */
    ExternalCalls::ExternalCall getCall() { result = call }
  }

  /**
   * Taint source: Parameters of externally callable functions.
   */
  class ParameterTaintSource extends TaintSource {
    Solidity::Parameter param;

    ParameterTaintSource() {
      this = TParameterNode(param) and
      exists(Solidity::FunctionDefinition func |
        param.getParent() = func and
        isExternallyCallable(func)
      )
    }

    override string getSourceType() {
      result = "external function parameter"
    }

    /** Gets the parameter. */
    Solidity::Parameter getParameter() { result = param }
  }

  /**
   * Holds if `func` is externally callable (public or external).
   */
  private predicate isExternallyCallable(Solidity::FunctionDefinition func) {
    exists(Solidity::AstNode visNode, Solidity::AstNode vis |
      visNode.getParent() = func and
      visNode.toString() = "Visibility" and
      vis.getParent() = visNode and
      (vis.getValue() = "external" or vis.getValue() = "public")
    )
  }

  /**
   * Taint sink: External call arguments (data leaving contract).
   */
  class ExternalCallArgumentSink extends TaintSink {
    ExternalCalls::ExternalCall call;
    int argIndex;

    ExternalCallArgumentSink() {
      this.asExpr() = call.getChild(argIndex) and
      argIndex >= 0
    }

    override string getSinkType() {
      if call.isLowLevel()
      then result = "low-level call data"
      else result = "external call argument"
    }
  }

  /**
   * Taint sink: Address in delegatecall.
   */
  class DelegatecallAddressSink extends TaintSink {
    DelegatecallAddressSink() {
      exists(ExternalCalls::ExternalCall call |
        call.isDelegateCall() and
        this.asExpr() = call.getTargetAddress()
      )
    }

    override string getSinkType() {
      result = "delegatecall target address"
    }
  }

  /**
   * Taint sink: Value sent in external call.
   */
  class ValueSentSink extends TaintSink {
    ValueSentSink() {
      exists(ExternalCalls::ExternalCall call |
        this.asExpr() = call.getValueSent()
      )
    }

    override string getSinkType() {
      result = "ether transfer amount"
    }
  }

  /**
   * Taint sink: selfdestruct argument.
   */
  class SelfdestructSink extends TaintSink {
    SelfdestructSink() {
      exists(Solidity::CallExpression call |
        call.getFunction().(Solidity::Identifier).getValue() = "selfdestruct" and
        this.asExpr() = call.getChild(0)
      )
    }

    override string getSinkType() {
      result = "selfdestruct beneficiary"
    }
  }

  /**
   * Taint sink: Array index (potential out-of-bounds).
   */
  class ArrayIndexSink extends TaintSink {
    ArrayIndexSink() {
      exists(Solidity::ArrayAccess access |
        this.asExpr() = access.getIndex()
      )
    }

    override string getSinkType() {
      result = "array index"
    }
  }

  /**
   * Taint barrier: Validated by require with comparison.
   */
  class RequireBarrier extends TaintBarrier {
    RequireBarrier() {
      exists(
        Solidity::CallExpression req,
        Solidity::Identifier reqId,
        Solidity::BinaryExpression check,
        Solidity::Identifier varRef
      |
        reqId = req.getFunction().getAChild*() and
        reqId.getValue() = "require" and
        check.getParent+() = req and
        varRef.getParent+() = check and
        this.asExpr() = varRef
      )
    }

    override string getBarrierReason() {
      result = "validated by require"
    }
  }

  /**
   * Taint barrier: Validated by assert.
   */
  class AssertBarrier extends TaintBarrier {
    AssertBarrier() {
      exists(
        Solidity::CallExpression assertCall,
        Solidity::Identifier assertId,
        Solidity::Identifier varRef
      |
        assertId = assertCall.getFunction().getAChild*() and
        assertId.getValue() = "assert" and
        varRef.getParent+() = assertCall and
        this.asExpr() = varRef
      )
    }

    override string getBarrierReason() {
      result = "validated by assert"
    }
  }

  /**
   * Holds if taint propagates from `nodeFrom` to `nodeTo` through an operation.
   *
   * This captures taint propagation through arithmetic, string operations, etc.
   */
  predicate taintStep(Node nodeFrom, Node nodeTo) {
    // Arithmetic operations propagate taint
    arithmeticTaintStep(nodeFrom, nodeTo) or
    // Bitwise operations propagate taint
    bitwiseTaintStep(nodeFrom, nodeTo) or
    // String/bytes operations propagate taint
    stringTaintStep(nodeFrom, nodeTo) or
    // ABI encoding propagates taint
    abiEncodeTaintStep(nodeFrom, nodeTo) or
    // Hashing propagates taint
    hashTaintStep(nodeFrom, nodeTo) or
    // Array/mapping access propagates taint
    collectionTaintStep(nodeFrom, nodeTo) or
    // Type conversion propagates taint
    typeConversionTaintStep(nodeFrom, nodeTo)
  }

  /**
   * Arithmetic operations propagate taint.
   */
  private predicate arithmeticTaintStep(Node nodeFrom, Node nodeTo) {
    exists(Solidity::BinaryExpression binOp |
      binOp.getOperator().(Solidity::AstNode).getValue() in ["+", "-", "*", "/", "%", "**"] and
      (nodeFrom.asExpr() = binOp.getLeft() or nodeFrom.asExpr() = binOp.getRight()) and
      nodeTo.asExpr() = binOp
    )
    or
    // Unary arithmetic
    exists(Solidity::UnaryExpression unary |
      unary.getOperator().toString() in ["-", "++", "--"] and
      nodeFrom.asExpr() = unary.getArgument() and
      nodeTo.asExpr() = unary
    )
    or
    // Augmented assignment (+=, -=, etc.)
    // The operator is stored as a child node
    exists(Solidity::AugmentedAssignmentExpression aug, Solidity::AstNode op |
      op.getParent() = aug and
      op.getValue() in ["+=", "-=", "*=", "/=", "%="] and
      nodeFrom.asExpr() = aug.getRight() and
      nodeTo.asExpr() = aug.getLeft()
    )
  }

  /**
   * Bitwise operations propagate taint.
   */
  private predicate bitwiseTaintStep(Node nodeFrom, Node nodeTo) {
    exists(Solidity::BinaryExpression binOp |
      binOp.getOperator().(Solidity::AstNode).getValue() in ["&", "|", "^", "<<", ">>"] and
      (nodeFrom.asExpr() = binOp.getLeft() or nodeFrom.asExpr() = binOp.getRight()) and
      nodeTo.asExpr() = binOp
    )
  }

  /**
   * String/bytes operations propagate taint.
   */
  private predicate stringTaintStep(Node nodeFrom, Node nodeTo) {
    exists(Solidity::CallExpression call, Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      (
        // string.concat, bytes.concat
        member.getProperty().(Solidity::AstNode).getValue() = "concat"
        or
        // abi.encodePacked (often used for string concat)
        member.getObject().(Solidity::Identifier).getValue() = "abi" and
        member.getProperty().(Solidity::AstNode).getValue() = "encodePacked"
      ) and
      nodeFrom.asExpr() = call.getChild(_) and
      nodeTo.asExpr() = call
    )
  }

  /**
   * ABI encoding propagates taint.
   */
  private predicate abiEncodeTaintStep(Node nodeFrom, Node nodeTo) {
    exists(Solidity::CallExpression call, Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getObject().(Solidity::Identifier).getValue() = "abi" and
      member.getProperty().(Solidity::AstNode).getValue() in [
        "encode", "encodePacked", "encodeWithSelector", "encodeWithSignature", "encodeCall"
      ] and
      nodeFrom.asExpr() = call.getChild(_) and
      nodeTo.asExpr() = call
    )
    or
    // abi.decode - input taint flows to output
    exists(Solidity::CallExpression call, Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getObject().(Solidity::Identifier).getValue() = "abi" and
      member.getProperty().(Solidity::AstNode).getValue() = "decode" and
      nodeFrom.asExpr() = call.getChild(0) and
      nodeTo.asExpr() = call
    )
  }

  /**
   * Hashing operations propagate taint.
   */
  private predicate hashTaintStep(Node nodeFrom, Node nodeTo) {
    exists(Solidity::CallExpression call |
      call.getFunction().(Solidity::Identifier).getValue() in ["keccak256", "sha256", "ripemd160"] and
      nodeFrom.asExpr() = call.getChild(0) and
      nodeTo.asExpr() = call
    )
  }

  /**
   * Collection access propagates taint.
   */
  private predicate collectionTaintStep(Node nodeFrom, Node nodeTo) {
    // Array access: taint from index affects result (for range checks)
    exists(Solidity::ArrayAccess access |
      nodeFrom.asExpr() = access.getIndex() and
      nodeTo.asExpr() = access
    )
    or
    // Array access: taint from base affects result
    exists(Solidity::ArrayAccess access |
      nodeFrom.asExpr() = access.getBase() and
      nodeTo.asExpr() = access
    )
    or
    // Member access: taint from object affects result
    exists(Solidity::MemberExpression member |
      nodeFrom.asExpr() = member.getObject() and
      nodeTo.asExpr() = member
    )
  }

  /**
   * Type conversion propagates taint.
   */
  private predicate typeConversionTaintStep(Node nodeFrom, Node nodeTo) {
    // Explicit type cast: uint256(x), address(x), etc.
    exists(Solidity::CallExpression cast |
      isCast(cast) and
      nodeFrom.asExpr() = cast.getChild(0) and
      nodeTo.asExpr() = cast
    )
    or
    // TypeCastExpression
    exists(Solidity::TypeCastExpression cast |
      nodeFrom.asExpr() = cast.getAFieldOrChild() and
      nodeTo.asExpr() = cast
    )
  }

  /**
   * Holds if `call` is a type cast expression.
   */
  private predicate isCast(Solidity::CallExpression call) {
    call.getFunction() instanceof Solidity::PrimitiveType or
    call.getFunction().(Solidity::Identifier).getValue() in [
      "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
      "int", "int8", "int16", "int32", "int64", "int128", "int256",
      "address", "bool", "bytes", "bytes1", "bytes32", "string"
    ]
  }

  /**
   * Holds if there is a taint path from `source` to `sink`.
   *
   * This combines local flow, inter-procedural flow, and taint steps.
   */
  predicate hasTaintFlow(TaintSource source, TaintSink sink) {
    exists(Node mid |
      source = mid and
      taintReaches(mid, sink)
    )
  }

  /**
   * Holds if taint from `node` can reach `sink`.
   */
  private predicate taintReaches(Node node, Node sink) {
    node = sink
    or
    not node instanceof TaintBarrier and
    exists(Node next |
      (
        localFlowStep(node, next) or
        taintStep(node, next) or
        jumpStep(node, next)
      ) and
      taintReaches(next, sink)
    )
  }

  /**
   * Gets all sinks reachable from a taint source.
   */
  TaintSink getReachableSink(TaintSource source) {
    hasTaintFlow(source, result)
  }

  /**
   * Gets all sources that can reach a taint sink.
   */
  TaintSource getSourceFor(TaintSink sink) {
    hasTaintFlow(result, sink)
  }
}
