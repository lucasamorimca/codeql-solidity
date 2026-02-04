/**
 * @name User input to external call
 * @description Tracks user-controlled data flowing to external calls
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id solidity/user-input-to-external-call
 * @tags security
 *       external/cwe/cwe-20
 *       taint-tracking
 */

import codeql.solidity.ast.internal.TreeSitter
import codeql.solidity.dataflow.TaintTracking
import codeql.solidity.dataflow.DataFlow
import codeql.solidity.callgraph.ExternalCalls

/**
 * Taint tracking configuration for user input to external calls.
 *
 * Sources: msg.sender, msg.value, msg.data, tx.origin, function parameters
 * Sinks: Arguments to low-level external calls
 * Sanitizers: require() statements, validation checks
 */
class UserInputToExternalCallConfig extends TaintTrackingConfiguration {
  UserInputToExternalCallConfig() { this = "UserInputToExternalCallConfig" }

  /**
   * Defines taint sources - user-controlled input.
   */
  override predicate isSource(DataFlow::Node source) {
    // msg.sender - caller address
    source.isMsgSender()
    or
    // msg.value - ether sent
    source.isMsgValue()
    or
    // msg.data - calldata
    source.isMsgData()
    or
    // tx.origin - transaction originator
    source.isTxOrigin()
    or
    // Function parameters
    exists(Solidity::Parameter p | source.asParameter() = p)
  }

  /**
   * Defines taint sinks - dangerous operations.
   */
  override predicate isSink(DataFlow::Node sink) {
    // Arguments to low-level calls
    exists(Solidity::CallExpression call |
      ExternalCalls::isLowLevelCall(call) and
      sink.asExpr() = call.getAnArgument().getAChild*()
    )
    or
    // Address in .call{value: X}(data)
    exists(Solidity::CallExpression call, Solidity::MemberExpression member |
      member = call.getFunction() and
      member.getProperty().(Solidity::AstNode).getValue() = "call" and
      sink.asExpr() = member.getObject()
    )
  }

  /**
   * Defines sanitizers - validation points that stop taint.
   */
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
    // Comparison in if condition
    exists(Solidity::IfStatement ifStmt, Solidity::BinaryExpression cmp |
      cmp = ifStmt.getCondition().getAChild*() and
      cmp.getOperator().(Solidity::AstNode).getValue() in ["==", "!=", "<", ">", "<=", ">="] and
      node.asExpr() = cmp.getAChild*()
    )
  }

  /**
   * Defines additional taint steps for non-standard flow.
   */
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Taint through array indexing
    exists(Solidity::SubscriptExpression sub |
      pred.asExpr() = sub.getIndex() and
      succ.asExpr() = sub
    )
    or
    // Taint through struct member access
    exists(Solidity::MemberExpression member |
      pred.asExpr() = member.getObject() and
      succ.asExpr() = member
    )
    or
    // Taint through keccak256 hashing
    exists(Solidity::CallExpression hash |
      hash.getFunction().(Solidity::Identifier).getValue() = "keccak256" and
      pred.asExpr() = hash.getAnArgument().getAChild*() and
      succ.asExpr() = hash
    )
    or
    // Taint through abi.encode
    exists(Solidity::CallExpression encode, Solidity::MemberExpression member |
      member = encode.getFunction() and
      member.getObject().(Solidity::Identifier).getValue() = "abi" and
      member.getProperty().(Solidity::AstNode).getValue().matches("encode%") and
      pred.asExpr() = encode.getAnArgument().getAChild*() and
      succ.asExpr() = encode
    )
  }
}

from UserInputToExternalCallConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, source, sink,
  "User-controlled data from $@ flows to external call", source, "user input"
