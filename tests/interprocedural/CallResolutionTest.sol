// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test file for Call Resolution
 *
 * TRUE POSITIVES (TP_): Calls that SHOULD be resolved
 * FALSE POSITIVES (FP_): Calls that should NOT be resolved (external/unknown)
 * EDGE CASES (EC_): Boundary conditions
 */

// =============================================================================
// TRUE POSITIVES - Internal Calls
// =============================================================================

contract TP_InternalCalls {
    uint256 public value;

    // TP: Direct internal call - should resolve
    function helper(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }

    function caller() public pure returns (uint256) {
        return helper(5);  // TP: Should resolve to helper
    }

    // TP: Private function call - should resolve
    function privateHelper(uint256 x) private pure returns (uint256) {
        return x + 1;
    }

    function callPrivate() public pure returns (uint256) {
        return privateHelper(10);  // TP: Should resolve to privateHelper
    }

    // TP: Public function calling public - should resolve
    function publicHelper() public pure returns (uint256) {
        return 42;
    }

    function callPublic() public pure returns (uint256) {
        return publicHelper();  // TP: Should resolve to publicHelper
    }

    // TP: Chained internal calls - all should resolve
    function chain1(uint256 x) internal pure returns (uint256) {
        return x + 1;
    }

    function chain2(uint256 x) internal pure returns (uint256) {
        return chain1(x) * 2;  // TP: Should resolve to chain1
    }

    function chainCaller() public pure returns (uint256) {
        return chain2(5);  // TP: Should resolve to chain2
    }
}

// =============================================================================
// TRUE POSITIVES - Inherited Function Calls
// =============================================================================

contract TP_BaseContract {
    function baseFunction() public virtual pure returns (uint256) {
        return 100;
    }

    function internalBase() internal pure returns (uint256) {
        return 50;
    }
}

contract TP_DerivedContract is TP_BaseContract {
    // TP: Call to inherited function - should resolve
    function callInherited() public pure returns (uint256) {
        return baseFunction();  // TP: Should resolve to TP_BaseContract.baseFunction
    }

    // TP: Call to inherited internal - should resolve
    function callInheritedInternal() public pure returns (uint256) {
        return internalBase();  // TP: Should resolve to TP_BaseContract.internalBase
    }
}

contract TP_OverrideContract is TP_BaseContract {
    // Override the base function
    function baseFunction() public pure override returns (uint256) {
        return 200;
    }

    // TP: Should resolve to THIS contract's override
    function callOverridden() public pure returns (uint256) {
        return baseFunction();  // TP: Should resolve to TP_OverrideContract.baseFunction
    }
}

// =============================================================================
// TRUE POSITIVES - Super Calls
// =============================================================================

contract TP_SuperBase {
    uint256 public value;

    function setValue(uint256 v) public virtual {
        value = v;
    }
}

contract TP_SuperDerived is TP_SuperBase {
    function setValue(uint256 v) public override {
        value = v * 2;
    }

    // TP: Super call - should resolve to base
    function callSuper(uint256 v) public {
        super.setValue(v);  // TP: Should resolve to TP_SuperBase.setValue
    }
}

contract TP_SuperChain is TP_SuperDerived {
    function setValue(uint256 v) public override {
        value = v * 3;
    }

    // TP: Super call in deeper inheritance - should resolve to immediate parent
    function callSuperChain(uint256 v) public {
        super.setValue(v);  // TP: Should resolve to TP_SuperDerived.setValue
    }
}

// =============================================================================
// TRUE POSITIVES - This Calls (External Self-Calls)
// =============================================================================

contract TP_ThisCalls {
    uint256 public value;

    function externalFunc() external returns (uint256) {
        value = 100;
        return value;
    }

    // TP: this.func() - should resolve
    function callThis() public returns (uint256) {
        return this.externalFunc();  // TP: Should resolve to externalFunc
    }

    function anotherExternal(uint256 x) external pure returns (uint256) {
        return x * 2;
    }

    // TP: this.func(args) - should resolve with args
    function callThisWithArgs() public pure returns (uint256) {
        return this.anotherExternal(5);  // TP: Should resolve to anotherExternal
    }
}

// =============================================================================
// TRUE POSITIVES - Multiple Inheritance
// =============================================================================

contract TP_MultiBase1 {
    function func1() public virtual pure returns (uint256) {
        return 1;
    }
}

contract TP_MultiBase2 {
    function func2() public virtual pure returns (uint256) {
        return 2;
    }
}

contract TP_MultiDerived is TP_MultiBase1, TP_MultiBase2 {
    // TP: Call to function from first base
    function callFunc1() public pure returns (uint256) {
        return func1();  // TP: Should resolve to TP_MultiBase1.func1
    }

    // TP: Call to function from second base
    function callFunc2() public pure returns (uint256) {
        return func2();  // TP: Should resolve to TP_MultiBase2.func2
    }
}

// =============================================================================
// FALSE POSITIVES - Calls That Should NOT Resolve
// =============================================================================

interface FP_IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract FP_ExternalCalls {
    FP_IToken public token;
    address public externalContract;

    constructor(address _token) {
        token = FP_IToken(_token);
    }

    // FP: Interface call - should NOT resolve (external contract)
    function transferTokens(address to, uint256 amount) external {
        token.transfer(to, amount);  // FP: Should NOT resolve - external
    }

    // FP: Interface view call - should NOT resolve
    function getBalance(address account) external view returns (uint256) {
        return token.balanceOf(account);  // FP: Should NOT resolve - external
    }

    // FP: Low-level call - should NOT resolve
    function lowLevelCall(bytes calldata data) external {
        (bool success, ) = externalContract.call(data);  // FP: Should NOT resolve
        require(success);
    }

    // FP: Delegatecall - should NOT resolve
    function delegateCall(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);  // FP: Should NOT resolve
        require(success);
    }

    // FP: Staticcall - should NOT resolve
    function staticCall(address target, bytes calldata data) external view returns (bytes memory) {
        (bool success, bytes memory result) = target.staticcall(data);  // FP: Should NOT resolve
        require(success);
        return result;
    }
}

contract FP_BuiltinCalls {
    // FP: Built-in functions should NOT be in call resolution results
    function testRequire(uint256 x) external pure {
        require(x > 0, "Must be positive");  // FP: Built-in
    }

    function testAssert(uint256 x) external pure {
        assert(x != 0);  // FP: Built-in
    }

    function testRevert() external pure {
        revert("Error");  // FP: Built-in
    }

    function testKeccak(bytes calldata data) external pure returns (bytes32) {
        return keccak256(data);  // FP: Built-in
    }

    function testAbi(uint256 x) external pure returns (bytes memory) {
        return abi.encode(x);  // FP: Built-in
    }

    function testEcrecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external pure returns (address) {
        return ecrecover(hash, v, r, s);  // FP: Built-in
    }
}

// =============================================================================
// EDGE CASES - Tricky Scenarios
// =============================================================================

contract EC_SameName {
    // EC: Function with same name but different signatures
    function overloaded(uint256 x) public pure returns (uint256) {
        return x;
    }

    function overloaded(uint256 x, uint256 y) public pure returns (uint256) {
        return x + y;
    }

    // Should resolve to correct overload
    function callOverload1() public pure returns (uint256) {
        return overloaded(5);  // EC: Should resolve to first overload
    }

    function callOverload2() public pure returns (uint256) {
        return overloaded(5, 10);  // EC: Should resolve to second overload
    }
}

contract EC_RecursiveCalls {
    // EC: Recursive function - should resolve to itself
    function factorial(uint256 n) public pure returns (uint256) {
        if (n <= 1) return 1;
        return n * factorial(n - 1);  // EC: Should resolve to itself
    }

    // EC: Mutual recursion
    function isEven(uint256 n) public pure returns (bool) {
        if (n == 0) return true;
        return isOdd(n - 1);  // EC: Should resolve to isOdd
    }

    function isOdd(uint256 n) public pure returns (bool) {
        if (n == 0) return false;
        return isEven(n - 1);  // EC: Should resolve to isEven
    }
}

contract EC_LibraryBase {
    function libFunc() internal pure returns (uint256) {
        return 42;
    }
}

library EC_TestLibrary {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

contract EC_LibraryCalls {
    using EC_TestLibrary for uint256;

    // EC: Library function via using - complex resolution
    function testLibrary(uint256 a, uint256 b) public pure returns (uint256) {
        return a.add(b);  // EC: Library call via using
    }

    // EC: Direct library call
    function testDirectLibrary(uint256 a, uint256 b) public pure returns (uint256) {
        return EC_TestLibrary.add(a, b);  // EC: Direct library call
    }
}

contract EC_VirtualDispatch {
    function virtualFunc() public virtual pure returns (string memory) {
        return "base";
    }
}

contract EC_VirtualDerived1 is EC_VirtualDispatch {
    function virtualFunc() public pure override returns (string memory) {
        return "derived1";
    }
}

contract EC_VirtualDerived2 is EC_VirtualDerived1 {
    // Does NOT override - uses EC_VirtualDerived1's implementation
    function callVirtual() public pure returns (string memory) {
        return virtualFunc();  // EC: Should resolve to EC_VirtualDerived1.virtualFunc
    }
}

contract EC_VirtualDerived3 is EC_VirtualDerived1 {
    function virtualFunc() public pure override returns (string memory) {
        return "derived3";
    }

    // EC: Should resolve to THIS contract's version
    function callVirtual() public pure returns (string memory) {
        return virtualFunc();  // EC: Should resolve to EC_VirtualDerived3.virtualFunc
    }
}

// =============================================================================
// EDGE CASES - Constructor Calls
// =============================================================================

contract EC_ConstructorBase {
    uint256 public baseValue;

    constructor(uint256 v) {
        baseValue = v;
    }

    function setBase(uint256 v) internal {
        baseValue = v;
    }
}

contract EC_ConstructorDerived is EC_ConstructorBase {
    uint256 public derivedValue;

    constructor(uint256 b, uint256 d) EC_ConstructorBase(b) {
        derivedValue = d;
        setBase(b * 2);  // EC: Internal call from constructor - should resolve
    }
}

// =============================================================================
// EDGE CASES - Modifier Context
// =============================================================================

contract EC_ModifierCalls {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function internalHelper() internal pure returns (uint256) {
        return 100;
    }

    // EC: Call inside modifier-protected function - should still resolve
    function protectedFunction() public onlyOwner returns (uint256) {
        return internalHelper();  // EC: Should resolve despite modifier
    }
}

// =============================================================================
// EDGE CASES - Fallback and Receive
// =============================================================================

contract EC_SpecialFunctions {
    uint256 public value;

    function internalSet(uint256 v) internal {
        value = v;
    }

    // EC: Call from receive - should resolve
    receive() external payable {
        internalSet(msg.value);  // EC: Should resolve to internalSet
    }

    // EC: Call from fallback - should resolve
    fallback() external payable {
        internalSet(1);  // EC: Should resolve to internalSet
    }
}

// =============================================================================
// EDGE CASES - Abstract Contracts
// =============================================================================

abstract contract EC_AbstractBase {
    function abstractFunc() public virtual returns (uint256);

    function concreteFunc() public pure returns (uint256) {
        return 42;
    }

    // EC: Call to concrete from abstract - should resolve
    function callConcrete() public pure returns (uint256) {
        return concreteFunc();  // EC: Should resolve
    }
}

contract EC_ConcreteImpl is EC_AbstractBase {
    function abstractFunc() public pure override returns (uint256) {
        return 100;
    }

    // EC: Call to implemented abstract - should resolve
    function callAbstract() public pure returns (uint256) {
        return abstractFunc();  // EC: Should resolve to EC_ConcreteImpl.abstractFunc
    }
}
