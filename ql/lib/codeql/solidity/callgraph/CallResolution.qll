/**
 * Provides call resolution for Solidity function calls.
 *
 * This module resolves call expressions to their target function definitions,
 * supporting internal calls, inherited function calls, and member calls.
 */

private import codeql.solidity.ast.internal.TreeSitter
private import codeql.solidity.ast.Contract
private import codeql.solidity.ast.Function
private import InheritanceGraph

/**
 * Gets the function name from a function definition.
 */
private string getFunctionName(Solidity::FunctionDefinition func) {
  result = func.getName().(Solidity::AstNode).getValue()
}

/**
 * Gets the contract name from a contract declaration.
 */
private string getContractName(Solidity::ContractDeclaration contract) {
  result = contract.getName().(Solidity::AstNode).getValue()
}

/**
 * Holds if `call` is a direct internal function call within `contract`.
 */
private predicate isInternalCall(
  Solidity::CallExpression call,
  Solidity::ContractDeclaration contract,
  string funcName
) {
  exists(Solidity::Identifier funcId |
    funcId = call.getFunction().getAChild*() and
    funcName = funcId.getValue() and
    call.getParent+() = contract and
    // Not a member expression (not x.func())
    not call.getFunction() instanceof Solidity::MemberExpression
  )
}

/**
 * Holds if `call` is a member function call (e.g., contract.func()).
 */
private predicate isMemberCall(
  Solidity::CallExpression call,
  Solidity::MemberExpression member,
  string funcName
) {
  member = call.getFunction().getAChild*() and
  funcName = member.getProperty().(Solidity::AstNode).getValue()
}

/**
 * Holds if `call` is a super call (super.func()).
 */
private predicate isSuperCall(
  Solidity::CallExpression call,
  string funcName
) {
  exists(Solidity::MemberExpression member |
    member = call.getFunction().getAChild*() and
    member.getObject().(Solidity::Identifier).getValue() = "super" and
    funcName = member.getProperty().(Solidity::AstNode).getValue()
  )
}

/**
 * Holds if `call` is a this call (this.func()).
 */
private predicate isThisCall(
  Solidity::CallExpression call,
  string funcName
) {
  exists(Solidity::MemberExpression member |
    member = call.getFunction().getAChild*() and
    member.getObject().(Solidity::Identifier).getValue() = "this" and
    funcName = member.getProperty().(Solidity::AstNode).getValue()
  )
}

/**
 * Module for resolving function calls to their targets.
 */
module CallResolution {
  /**
   * Resolves a direct internal function call to its target within the same contract.
   *
   * Example: `doSomething()` within contract Foo resolves to `function doSomething()` in Foo.
   */
  predicate resolveInternalCall(Solidity::CallExpression call, Solidity::FunctionDefinition target) {
    exists(Solidity::ContractDeclaration contract, string funcName |
      isInternalCall(call, contract, funcName) and
      target.getParent+() = contract and
      getFunctionName(target) = funcName
    )
  }

  /**
   * Resolves a function call to an inherited function.
   *
   * Example: If contract B inherits from A, and B calls `foo()` which is defined in A,
   * this resolves to A.foo().
   */
  predicate resolveInheritedCall(Solidity::CallExpression call, Solidity::FunctionDefinition target) {
    exists(Solidity::ContractDeclaration callerContract, string funcName |
      isInternalCall(call, callerContract, funcName) and
      // Function is not defined in the caller contract
      not exists(Solidity::FunctionDefinition localFunc |
        localFunc.getParent+() = callerContract and
        getFunctionName(localFunc) = funcName
      ) and
      // But is defined in a base contract
      exists(Solidity::ContractDeclaration baseContract |
        baseContract = InheritanceGraph::getInheritanceChain(callerContract) and
        baseContract != callerContract and
        target.getParent+() = baseContract and
        getFunctionName(target) = funcName
      )
    )
  }

  /**
   * Resolves a super.func() call to the base contract's function.
   */
  predicate resolveSuperCall(Solidity::CallExpression call, Solidity::FunctionDefinition target) {
    exists(Solidity::ContractDeclaration callerContract, string funcName |
      isSuperCall(call, funcName) and
      call.getParent+() = callerContract and
      // Find in direct base contracts first, then in their bases
      exists(Solidity::ContractDeclaration baseContract |
        baseContract = InheritanceGraph::getDirectBase(callerContract) and
        (
          // Function in direct base
          target.getParent+() = baseContract and
          getFunctionName(target) = funcName
          or
          // Function in ancestor of base
          exists(Solidity::ContractDeclaration ancestorBase |
            ancestorBase = InheritanceGraph::getInheritanceChain(baseContract) and
            ancestorBase != callerContract and
            target.getParent+() = ancestorBase and
            getFunctionName(target) = funcName and
            // Not overridden in closer base
            not exists(Solidity::FunctionDefinition closer |
              closer.getParent+() = InheritanceGraph::getInheritanceChain(baseContract) and
              closer.getParent+() != ancestorBase and
              getFunctionName(closer) = funcName and
              ancestorBase = InheritanceGraph::getInheritanceChain(closer.getParent+())
            )
          )
        )
      )
    )
  }

  /**
   * Resolves a this.func() call (external self-call).
   */
  predicate resolveThisCall(Solidity::CallExpression call, Solidity::FunctionDefinition target) {
    exists(Solidity::ContractDeclaration contract, string funcName |
      isThisCall(call, funcName) and
      call.getParent+() = contract and
      target.getParent+() = InheritanceGraph::getInheritanceChain(contract) and
      getFunctionName(target) = funcName and
      // Resolve to most derived (in caller contract or overridden)
      not exists(Solidity::FunctionDefinition moreSpecific |
        moreSpecific.getParent+() = InheritanceGraph::getInheritanceChain(contract) and
        getFunctionName(moreSpecific) = funcName and
        target.getParent+() = InheritanceGraph::getInheritanceChain(moreSpecific.getParent+()) and
        target != moreSpecific
      )
    )
  }

  /**
   * Resolves a member call where the base is a state variable of contract type.
   *
   * Example: `IToken token; token.transfer(...)` - resolves to IToken.transfer if known.
   */
  predicate resolveMemberCallToInterface(
    Solidity::CallExpression call,
    Solidity::FunctionDefinition target
  ) {
    exists(
      Solidity::MemberExpression member,
      string funcName,
      Solidity::Identifier base,
      Solidity::StateVariableDeclaration stateVar,
      Solidity::ContractDeclaration callerContract
    |
      isMemberCall(call, member, funcName) and
      base = member.getObject().getAChild*() and
      call.getParent+() = callerContract and
      stateVar.getParent+() = callerContract and
      stateVar.getName().(Solidity::AstNode).getValue() = base.getValue() and
      // Get the interface/contract type of the state variable
      exists(Solidity::Identifier typeId, Solidity::ContractDeclaration targetContract |
        typeId = stateVar.getType().getAChild*() and
        getContractName(targetContract) = typeId.getValue() and
        target.getParent+() = targetContract and
        getFunctionName(target) = funcName
      )
    )
  }

  /**
   * Resolves a member call where the base is a parameter of contract type.
   */
  predicate resolveMemberCallFromParameter(
    Solidity::CallExpression call,
    Solidity::FunctionDefinition target
  ) {
    exists(
      Solidity::MemberExpression member,
      string funcName,
      Solidity::Identifier base,
      Solidity::Parameter param,
      Solidity::FunctionDefinition callerFunc
    |
      isMemberCall(call, member, funcName) and
      base = member.getObject().getAChild*() and
      call.getParent+() = callerFunc and
      param.getParent() = callerFunc and
      param.getName().(Solidity::AstNode).getValue() = base.getValue() and
      // Get the interface/contract type of the parameter
      exists(Solidity::Identifier typeId, Solidity::ContractDeclaration targetContract |
        typeId = param.getType().getAChild*() and
        getContractName(targetContract) = typeId.getValue() and
        target.getParent+() = targetContract and
        getFunctionName(target) = funcName
      )
    )
  }

  /**
   * Main call resolution predicate - union of all resolution strategies.
   *
   * This predicate resolves a call expression to all possible target functions.
   * For virtual calls, multiple targets may be returned.
   */
  predicate resolveCall(Solidity::CallExpression call, Solidity::FunctionDefinition target) {
    resolveInternalCall(call, target) or
    resolveInheritedCall(call, target) or
    resolveSuperCall(call, target) or
    resolveThisCall(call, target) or
    resolveMemberCallToInterface(call, target) or
    resolveMemberCallFromParameter(call, target)
  }

  /**
   * Holds if `call` can be resolved to at least one target.
   */
  predicate isResolvable(Solidity::CallExpression call) {
    resolveCall(call, _)
  }

  /**
   * Holds if `call` cannot be resolved (e.g., external call to unknown contract).
   */
  predicate isUnresolved(Solidity::CallExpression call) {
    // Has function call structure but not resolvable
    exists(call.getFunction()) and
    not isResolvable(call) and
    // Not a built-in function
    not isBuiltinCall(call)
  }

  /**
   * Holds if `call` is a call to a Solidity built-in function.
   */
  predicate isBuiltinCall(Solidity::CallExpression call) {
    exists(Solidity::Identifier id |
      id = call.getFunction().getAChild*() and
      id.getValue() in [
        "require", "assert", "revert",
        "keccak256", "sha256", "ripemd160",
        "ecrecover", "addmod", "mulmod",
        "selfdestruct", "blockhash",
        "gasleft", "address", "payable"
      ]
    )
    or
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      member.getObject().(Solidity::Identifier).getValue() in ["abi", "block", "msg", "tx", "type"]
    )
  }

  /**
   * Holds if `call` is a call to a known external library function.
   * This provides stub support for common libraries like OpenZeppelin.
   */
  predicate isKnownLibraryCall(Solidity::CallExpression call, string libraryName, string funcName) {
    exists(Solidity::MemberExpression member |
      member = call.getFunction().getAChild*() and
      funcName = member.getProperty().(Solidity::AstNode).getValue() and
      (
        // OpenZeppelin SafeMath
        member.getObject().(Solidity::Identifier).getValue() = "SafeMath" and
        libraryName = "SafeMath" and
        funcName in ["add", "sub", "mul", "div", "mod", "tryAdd", "trySub", "tryMul", "tryDiv", "tryMod"]
        or
        // OpenZeppelin Address library
        member.getObject().(Solidity::Identifier).getValue() = "Address" and
        libraryName = "Address" and
        funcName in ["isContract", "sendValue", "functionCall", "functionCallWithValue",
                     "functionStaticCall", "functionDelegateCall"]
        or
        // OpenZeppelin SafeERC20
        member.getObject().(Solidity::Identifier).getValue() = "SafeERC20" and
        libraryName = "SafeERC20" and
        funcName in ["safeTransfer", "safeTransferFrom", "safeApprove",
                     "safeIncreaseAllowance", "safeDecreaseAllowance"]
        or
        // OpenZeppelin ECDSA
        member.getObject().(Solidity::Identifier).getValue() = "ECDSA" and
        libraryName = "ECDSA" and
        funcName in ["recover", "toEthSignedMessageHash", "toTypedDataHash"]
        or
        // OpenZeppelin Strings
        member.getObject().(Solidity::Identifier).getValue() = "Strings" and
        libraryName = "Strings" and
        funcName in ["toString", "toHexString"]
      )
    )
  }

  /**
   * Holds if `call` is a library call that propagates taint from first argument to result.
   * Used for taint tracking through library functions.
   */
  predicate libraryCallPropagatesTaint(Solidity::CallExpression call) {
    exists(string lib, string func |
      isKnownLibraryCall(call, lib, func) and
      (
        // SafeMath arithmetic operations propagate taint
        lib = "SafeMath" and func in ["add", "sub", "mul", "div", "mod"]
        or
        // Address.functionCall returns result, propagates taint
        lib = "Address" and func in ["functionCall", "functionCallWithValue", "functionStaticCall"]
        or
        // ECDSA.recover returns address from signature data
        lib = "ECDSA" and func = "recover"
      )
    )
  }

  /**
   * Holds if `call` is a library call that acts as a sanitizer.
   * These calls validate input and are typically safe after the call succeeds.
   */
  predicate libraryCallIsSanitizer(Solidity::CallExpression call) {
    exists(string lib, string func |
      isKnownLibraryCall(call, lib, func) and
      (
        // Address.isContract validates address
        lib = "Address" and func = "isContract"
        or
        // SafeERC20 validates return values
        lib = "SafeERC20"
      )
    )
  }
}
