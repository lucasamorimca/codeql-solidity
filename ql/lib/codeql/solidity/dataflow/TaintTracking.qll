/**
 * Provides classes and predicates for taint tracking analysis.
 *
 * Taint tracking extends data flow to track how "tainted" (potentially
 * malicious or user-controlled) data propagates through a program.
 */

/** Provides classes and predicates for taint tracking. */
module TaintTracking {
  private import codeql.solidity.ast.internal.TreeSitter
  private import codeql.solidity.dataflow.internal.DataFlowNodes
  private import codeql.solidity.dataflow.internal.DataFlowPrivate
  private import codeql.solidity.dataflow.DataFlow

  /**
   * A taint tracking configuration.
   *
   * Extend this class to define custom taint tracking analyses.
   */
  abstract class TaintTrackingConfiguration extends string {
    bindingset[this]
    TaintTrackingConfiguration() { any() }

    /**
     * Holds if `source` is a taint source for this configuration.
     */
    abstract predicate isSource(DataFlow::Node source);

    /**
     * Holds if `sink` is a taint sink for this configuration.
     */
    abstract predicate isSink(DataFlow::Node sink);

    /**
     * Holds if `node` is a sanitizer (barrier) for this configuration.
     */
    predicate isSanitizer(DataFlow::Node node) { none() }

    /**
     * Holds if there is additional taint flow from `pred` to `succ`.
     */
    predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) { none() }

    /**
     * Holds if tainted data can flow from `source` to `sink`.
     */
    predicate hasFlow(DataFlow::Node source, DataFlow::Node sink) {
      this.isSource(source) and
      this.isSink(sink) and
      taintFlow(this, source, sink)
    }

    /**
     * Holds if there is a flow path from `source` to `sink`.
     */
    predicate hasFlowPath(DataFlow::Node source, DataFlow::Node sink) {
      this.hasFlow(source, sink)
    }
  }

  /**
   * Internal predicate for taint flow with configuration.
   */
  private predicate taintFlow(
    TaintTrackingConfiguration config, DataFlow::Node source, DataFlow::Node sink
  ) {
    config.isSource(source) and
    not config.isSanitizer(source) and
    (
      source = sink and config.isSink(sink)
      or
      exists(DataFlow::Node mid |
        taintFlow(config, source, mid) and
        taintStep(mid, sink, config) and
        not config.isSanitizer(sink)
      )
    )
  }

  /**
   * Holds if there is a taint step from `pred` to `succ`.
   */
  private predicate taintStep(
    DataFlow::Node pred, DataFlow::Node succ, TaintTrackingConfiguration config
  ) {
    localFlowStep(pred, succ) or
    jumpStep(pred, succ) or
    additionalTaintStep(pred, succ) or
    config.isAdditionalTaintStep(pred, succ)
  }

  /**
   * Module containing Solidity-specific taint sources.
   */
  module TaintSources {
    /**
     * A taint source representing `msg.sender`.
     */
    class MsgSenderSource extends DataFlow::Node {
      MsgSenderSource() { this.isMsgSender() }
    }

    /**
     * A taint source representing `msg.value`.
     */
    class MsgValueSource extends DataFlow::Node {
      MsgValueSource() { this.isMsgValue() }
    }

    /**
     * A taint source representing `msg.data`.
     */
    class MsgDataSource extends DataFlow::Node {
      MsgDataSource() { this.isMsgData() }
    }

    /**
     * A taint source representing `tx.origin`.
     */
    class TxOriginSource extends DataFlow::Node {
      TxOriginSource() { this.isTxOrigin() }
    }

    /**
     * A taint source representing `block.timestamp`.
     */
    class BlockTimestampSource extends DataFlow::Node {
      BlockTimestampSource() { this.isBlockTimestamp() }
    }

    /**
     * A taint source representing function parameters (user input).
     */
    class ParameterSource extends DataFlow::ParameterNode {
      ParameterSource() {
        // Any function parameter is potentially user-controlled
        // More precise filtering could check visibility through getAFieldOrChild
        exists(Solidity::FunctionDefinition func |
          this.getParameter() = func.getAFieldOrChild() and
          this.getParameter() instanceof Solidity::Parameter
        )
      }
    }

    /**
     * A taint source representing external call return values.
     */
    class ExternalCallReturnSource extends DataFlow::Node {
      ExternalCallReturnSource() { this.isExternalCallResult() }
    }

    /**
     * Any user-controllable taint source.
     */
    class UserControlledSource extends DataFlow::Node {
      UserControlledSource() {
        this instanceof MsgSenderSource or
        this instanceof MsgValueSource or
        this instanceof MsgDataSource or
        this instanceof TxOriginSource or
        this instanceof ParameterSource or
        this instanceof ExternalCallReturnSource
      }
    }
  }

  /**
   * Module containing Solidity-specific taint sinks.
   */
  module TaintSinks {
    /**
     * A taint sink representing an external call target (address).
     */
    class ExternalCallTargetSink extends DataFlow::Node {
      Solidity::CallExpression call;

      ExternalCallTargetSink() {
        exists(Solidity::MemberExpression member |
          member = call.getFunction() and
          (
            member.getProperty().(Solidity::AstNode).toString() = "call" or
            member.getProperty().(Solidity::AstNode).toString() = "delegatecall" or
            member.getProperty().(Solidity::AstNode).toString() = "staticcall" or
            member.getProperty().(Solidity::AstNode).toString() = "transfer" or
            member.getProperty().(Solidity::AstNode).toString() = "send"
          ) and
          this.asExpr() = member.getObject()
        )
      }

      /** Gets the call expression. */
      Solidity::CallExpression getCall() { result = call }
    }

    /**
     * A taint sink representing call data (bytes parameter to low-level call).
     */
    class CallDataSink extends DataFlow::Node {
      Solidity::CallExpression call;

      CallDataSink() {
        exists(Solidity::MemberExpression member |
          member = call.getFunction() and
          (
            member.getProperty().(Solidity::AstNode).toString() = "call" or
            member.getProperty().(Solidity::AstNode).toString() = "delegatecall" or
            member.getProperty().(Solidity::AstNode).toString() = "staticcall"
          ) and
          this.asExpr() = call.getChild(0)
        )
      }

      /** Gets the call expression. */
      Solidity::CallExpression getCall() { result = call }
    }

    /**
     * A taint sink representing a selfdestruct argument.
     */
    class SelfdestructSink extends DataFlow::Node {
      SelfdestructSink() {
        exists(Solidity::CallExpression call |
          call.getFunction().(Solidity::Identifier).toString() = "selfdestruct" and
          this.asExpr() = call.getChild(0)
        )
      }
    }

    /**
     * A taint sink representing an Ether transfer amount.
     */
    class EtherTransferAmountSink extends DataFlow::Node {
      EtherTransferAmountSink() {
        // transfer(amount) or send(amount)
        exists(Solidity::CallExpression call, Solidity::MemberExpression member |
          member = call.getFunction() and
          (
            member.getProperty().(Solidity::AstNode).toString() = "transfer" or
            member.getProperty().(Solidity::AstNode).toString() = "send"
          ) and
          this.asExpr() = call.getChild(0)
        )
        // Note: .call{value: amount} pattern requires NamedArgument type support
      }
    }

    /**
     * A taint sink representing array index access.
     */
    class ArrayIndexSink extends DataFlow::Node {
      ArrayIndexSink() {
        exists(Solidity::ArrayAccess access |
          this.asExpr() = access.getChild(1) // the index expression
        )
      }
    }

    /**
     * A taint sink representing storage write.
     */
    class StorageWriteSink extends DataFlow::Node {
      StorageWriteSink() {
        exists(Solidity::AssignmentExpression assign, Solidity::StateVariableDeclaration decl |
          exists(Solidity::Identifier id |
            id = assign.getLeft() and
            id.toString() = decl.getName().(Solidity::AstNode).toString()
          ) and
          this.asExpr() = assign.getRight()
        )
      }
    }

    /**
     * A sink representing a critical state variable modification.
     */
    class CriticalStateModificationSink extends DataFlow::Node {
      CriticalStateModificationSink() {
        exists(Solidity::AssignmentExpression assign, Solidity::Identifier id |
          id = assign.getLeft() and
          this.asExpr() = assign.getRight() and
          // Look for common critical variable names
          (
            id.toString().toLowerCase().matches("%owner%") or
            id.toString().toLowerCase().matches("%admin%") or
            id.toString().toLowerCase().matches("%balance%") or
            id.toString().toLowerCase().matches("%allowance%")
          )
        )
      }
    }
  }

  /**
   * Module containing Solidity-specific sanitizers.
   */
  module TaintSanitizers {
    /**
     * A sanitizer representing a require/assert check.
     */
    class RequireCheckSanitizer extends DataFlow::Node {
      RequireCheckSanitizer() {
        exists(Solidity::CallExpression call |
          (
            call.getFunction().(Solidity::Identifier).toString() = "require" or
            call.getFunction().(Solidity::Identifier).toString() = "assert"
          ) and
          this.asExpr() = call.getChild(0)
        )
      }
    }

    /**
     * A sanitizer representing an onlyOwner-style modifier check.
     */
    class OwnerCheckSanitizer extends DataFlow::Node {
      OwnerCheckSanitizer() {
        exists(Solidity::BinaryExpression cmp |
          (
            cmp.getOperator().toString() = "==" or
            cmp.getOperator().toString() = "!="
          ) and
          this.asExpr() = cmp and
          (
            // msg.sender == owner pattern
            exists(Solidity::MemberExpression member, Solidity::Identifier id |
              member = cmp.getLeft() and
              member.getObject().(Solidity::Identifier).toString() = "msg" and
              member.getProperty().(Solidity::AstNode).toString() = "sender" and
              id = cmp.getRight() and
              id.toString().toLowerCase().matches("%owner%")
            )
            or
            exists(Solidity::MemberExpression member, Solidity::Identifier id |
              id = cmp.getLeft() and
              id.toString().toLowerCase().matches("%owner%") and
              member = cmp.getRight() and
              member.getObject().(Solidity::Identifier).toString() = "msg" and
              member.getProperty().(Solidity::AstNode).toString() = "sender"
            )
          )
        )
      }
    }

    /**
     * A sanitizer representing a bounds check.
     */
    class BoundsCheckSanitizer extends DataFlow::Node {
      BoundsCheckSanitizer() {
        exists(Solidity::CallExpression req, Solidity::BinaryExpression cmp |
          req.getFunction().(Solidity::Identifier).toString() = "require" and
          cmp = req.getChild(0) and
          (
            cmp.getOperator().toString() = "<" or
            cmp.getOperator().toString() = "<=" or
            cmp.getOperator().toString() = ">" or
            cmp.getOperator().toString() = ">="
          ) and
          this.asExpr() = cmp.getLeft()
        )
      }
    }

    /**
     * A sanitizer representing a reentrancy guard.
     */
    class ReentrancyGuardSanitizer extends DataFlow::Node {
      ReentrancyGuardSanitizer() {
        // Check for modifier that looks like a reentrancy guard
        exists(Solidity::ModifierInvocation mod |
          mod.toString().toLowerCase().matches("%nonreentrant%") or
          mod.toString().toLowerCase().matches("%reentrancyguard%")
        )
      }
    }
  }

  /**
   * Holds if there is taint flow from any source to any sink (without configuration).
   */
  predicate defaultTaintFlow(DataFlow::Node source, DataFlow::Node sink) {
    source instanceof TaintSources::UserControlledSource and
    (
      sink instanceof TaintSinks::ExternalCallTargetSink or
      sink instanceof TaintSinks::CallDataSink or
      sink instanceof TaintSinks::SelfdestructSink or
      sink instanceof TaintSinks::EtherTransferAmountSink
    ) and
    exists(DataFlow::Node mid |
      source = mid or
      (
        DataFlow::localFlow(source, mid) and
        (
          DataFlow::localFlow(mid, sink) or
          jumpStep(mid, sink) or
          additionalTaintStep(mid, sink)
        )
      )
    )
  }
}
