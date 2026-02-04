/**
 * Provides classes representing control flow completions.
 *
 * A completion represents how a statement or expression completes execution.
 * This is used to determine the successor of a control flow node.
 */

private import codeql.solidity.ast.internal.TreeSitter

/**
 * A completion of a statement or expression.
 */
newtype TCompletion =
  /** A normal completion - control continues to the next statement. */
  TNormalCompletion() or
  /** A return completion - control exits the function. */
  TReturnCompletion() or
  /** A break completion - control exits the innermost loop. */
  TBreakCompletion() or
  /** A continue completion - control jumps to loop condition. */
  TContinueCompletion() or
  /** A revert completion - control exits with revert. */
  TRevertCompletion() or
  /** A throw completion (legacy) - control exits with throw. */
  TThrowCompletion() or
  /** A Yul leave completion - control exits the current assembly function. */
  TYulLeaveCompletion() or
  /** A boolean completion - for conditions that branch. */
  TBooleanCompletion(boolean value) { value = true or value = false }

/**
 * A completion of a statement or expression.
 */
class Completion extends TCompletion {
  /** Gets a string representation of this completion. */
  string toString() {
    this = TNormalCompletion() and result = "normal"
    or
    this = TReturnCompletion() and result = "return"
    or
    this = TBreakCompletion() and result = "break"
    or
    this = TContinueCompletion() and result = "continue"
    or
    this = TRevertCompletion() and result = "revert"
    or
    this = TThrowCompletion() and result = "throw"
    or
    this = TYulLeaveCompletion() and result = "yul_leave"
    or
    exists(boolean b | this = TBooleanCompletion(b) | result = "boolean(" + b.toString() + ")")
  }

  /** Holds if this is a normal completion. */
  predicate isNormal() { this = TNormalCompletion() }

  /** Holds if this is a return completion. */
  predicate isReturn() { this = TReturnCompletion() }

  /** Holds if this is a break completion. */
  predicate isBreak() { this = TBreakCompletion() }

  /** Holds if this is a continue completion. */
  predicate isContinue() { this = TContinueCompletion() }

  /** Holds if this is a revert completion. */
  predicate isRevert() { this = TRevertCompletion() }

  /** Holds if this is a Yul leave completion. */
  predicate isYulLeave() { this = TYulLeaveCompletion() }

  /** Holds if this completion exits the current function. */
  predicate isAbnormal() {
    this.isReturn() or this.isRevert() or this = TThrowCompletion() or this.isYulLeave()
  }

  /** Holds if this completion exits the current loop. */
  predicate isLoopExit() {
    this.isBreak()
  }
}

/** A normal completion. */
class NormalCompletion extends Completion {
  NormalCompletion() { this = TNormalCompletion() }
}

/** A return completion. */
class ReturnCompletion extends Completion {
  ReturnCompletion() { this = TReturnCompletion() }
}

/** A break completion. */
class BreakCompletion extends Completion {
  BreakCompletion() { this = TBreakCompletion() }
}

/** A continue completion. */
class ContinueCompletion extends Completion {
  ContinueCompletion() { this = TContinueCompletion() }
}

/** A revert completion. */
class RevertCompletion extends Completion {
  RevertCompletion() { this = TRevertCompletion() }
}

/** A boolean completion (true or false branch). */
class BooleanCompletion extends Completion {
  boolean value;

  BooleanCompletion() { this = TBooleanCompletion(value) }

  /** Gets the boolean value of this completion. */
  boolean getValue() { result = value }
}

/** A true completion. */
class TrueCompletion extends BooleanCompletion {
  TrueCompletion() { value = true }
}

/** A false completion. */
class FalseCompletion extends BooleanCompletion {
  FalseCompletion() { value = false }
}

/** A Yul leave completion - exits the current Yul function. */
class YulLeaveCompletion extends Completion {
  YulLeaveCompletion() { this = TYulLeaveCompletion() }
}
