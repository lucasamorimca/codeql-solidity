// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test file for Inheritance Graph Analysis
 *
 * TRUE POSITIVES (TP_): Inheritance relationships that SHOULD be detected
 * FALSE POSITIVES (FP_): Relationships that should NOT be detected
 * EDGE CASES (EC_): Complex inheritance scenarios
 */

// =============================================================================
// TRUE POSITIVES - Simple Inheritance
// =============================================================================

contract TP_SimpleBase {
    uint256 public baseValue;

    function setBase(uint256 v) public virtual {
        baseValue = v;
    }
}

// TP: Single inheritance - should detect TP_SimpleDerived inherits from TP_SimpleBase
contract TP_SimpleDerived is TP_SimpleBase {
    uint256 public derivedValue;

    function setDerived(uint256 v) public {
        derivedValue = v;
    }
}

// =============================================================================
// TRUE POSITIVES - Chain Inheritance
// =============================================================================

contract TP_ChainA {
    function funcA() public virtual pure returns (string memory) {
        return "A";
    }
}

// TP: TP_ChainB inherits from TP_ChainA
contract TP_ChainB is TP_ChainA {
    function funcB() public virtual pure returns (string memory) {
        return "B";
    }
}

// TP: TP_ChainC inherits from both TP_ChainB AND TP_ChainA (transitive)
contract TP_ChainC is TP_ChainB {
    function funcC() public pure returns (string memory) {
        return "C";
    }
}

// TP: Four-level inheritance chain
contract TP_ChainD is TP_ChainC {
    function funcD() public pure returns (string memory) {
        return "D";
    }
}

// =============================================================================
// TRUE POSITIVES - Multiple Inheritance
// =============================================================================

contract TP_Multi1 {
    function m1() public virtual pure returns (uint256) {
        return 1;
    }
}

contract TP_Multi2 {
    function m2() public virtual pure returns (uint256) {
        return 2;
    }
}

contract TP_Multi3 {
    function m3() public virtual pure returns (uint256) {
        return 3;
    }
}

// TP: Multiple inheritance - should inherit from all three
contract TP_MultiDerived is TP_Multi1, TP_Multi2, TP_Multi3 {
    function call123() public pure returns (uint256) {
        return m1() + m2() + m3();
    }
}

// =============================================================================
// TRUE POSITIVES - Diamond Inheritance
// =============================================================================

contract TP_DiamondTop {
    function top() public virtual pure returns (string memory) {
        return "top";
    }
}

// TP: Left branch of diamond
contract TP_DiamondLeft is TP_DiamondTop {
    function left() public virtual pure returns (string memory) {
        return "left";
    }

    function top() public virtual override pure returns (string memory) {
        return "left-top";
    }
}

// TP: Right branch of diamond
contract TP_DiamondRight is TP_DiamondTop {
    function right() public virtual pure returns (string memory) {
        return "right";
    }

    function top() public virtual override pure returns (string memory) {
        return "right-top";
    }
}

// TP: Diamond bottom - inherits from both branches and transitively from top
contract TP_DiamondBottom is TP_DiamondLeft, TP_DiamondRight {
    function top() public pure override(TP_DiamondLeft, TP_DiamondRight) returns (string memory) {
        return "bottom-top";
    }

    function bottom() public pure returns (string memory) {
        return "bottom";
    }
}

// =============================================================================
// TRUE POSITIVES - Interface Inheritance
// =============================================================================

interface TP_IBase {
    function baseInterface() external view returns (uint256);
}

interface TP_IDerived is TP_IBase {
    function derivedInterface() external view returns (uint256);
}

// TP: Contract implementing derived interface inherits interface chain
contract TP_InterfaceImpl is TP_IDerived {
    function baseInterface() external pure override returns (uint256) {
        return 1;
    }

    function derivedInterface() external pure override returns (uint256) {
        return 2;
    }
}

// =============================================================================
// TRUE POSITIVES - Virtual/Override Detection
// =============================================================================

contract TP_VirtualBase {
    // TP: Virtual function - should be detected as virtual
    function virtualFunc() public virtual pure returns (uint256) {
        return 1;
    }

    // TP: Non-virtual function
    function nonVirtualFunc() public pure returns (uint256) {
        return 2;
    }
}

contract TP_OverrideContract is TP_VirtualBase {
    // TP: Override function - should be detected as override
    function virtualFunc() public pure override returns (uint256) {
        return 10;
    }
}

contract TP_VirtualOverride is TP_VirtualBase {
    // TP: Virtual override - both virtual AND override
    function virtualFunc() public virtual override pure returns (uint256) {
        return 100;
    }
}

contract TP_FinalOverride is TP_VirtualOverride {
    // TP: Final override in chain
    function virtualFunc() public pure override returns (uint256) {
        return 1000;
    }
}

// =============================================================================
// FALSE POSITIVES - No Inheritance
// =============================================================================

// FP: Standalone contract - should NOT appear in inheritance results
contract FP_Standalone {
    uint256 public value;

    function setValue(uint256 v) public {
        value = v;
    }
}

// FP: Another standalone - no inheritance relationship
contract FP_AnotherStandalone {
    uint256 public other;

    function setOther(uint256 v) public {
        other = v;
    }
}

// FP: Contracts with similar names but no inheritance
contract FP_Similar1 {
    function similar() public pure returns (uint256) {
        return 1;
    }
}

contract FP_Similar2 {
    function similar() public pure returns (uint256) {
        return 2;
    }
}

// =============================================================================
// FALSE POSITIVES - Composition (Not Inheritance)
// =============================================================================

contract FP_Component {
    function componentFunc() public pure returns (uint256) {
        return 42;
    }
}

// FP: Composition via state variable - NOT inheritance
contract FP_Composite {
    FP_Component public component;

    constructor(address _component) {
        component = FP_Component(_component);
    }

    // This is delegation, NOT inheritance
    function delegateCall() public view returns (uint256) {
        return component.componentFunc();
    }
}

// =============================================================================
// EDGE CASES - Abstract Contracts
// =============================================================================

// EC: Abstract contract in inheritance chain
abstract contract EC_AbstractBase {
    function abstractFunc() public virtual returns (uint256);

    function concreteFunc() public pure returns (uint256) {
        return 42;
    }
}

abstract contract EC_AbstractMiddle is EC_AbstractBase {
    function anotherAbstract() public virtual returns (string memory);
}

// EC: Concrete at end of abstract chain
contract EC_ConcreteEnd is EC_AbstractMiddle {
    function abstractFunc() public pure override returns (uint256) {
        return 100;
    }

    function anotherAbstract() public pure override returns (string memory) {
        return "concrete";
    }
}

// =============================================================================
// EDGE CASES - Library Inheritance (Not Applicable)
// =============================================================================

// EC: Libraries cannot inherit - should NOT appear in contract inheritance
library EC_LibraryA {
    function libFunc() internal pure returns (uint256) {
        return 1;
    }
}

// EC: Using library is NOT inheritance
contract EC_LibraryUser {
    using EC_LibraryA for uint256;

    function useLib() public pure returns (uint256) {
        return EC_LibraryA.libFunc();
    }
}

// =============================================================================
// EDGE CASES - Deep Inheritance Chain
// =============================================================================

contract EC_Deep1 {
    function d1() public virtual pure returns (uint256) { return 1; }
}

contract EC_Deep2 is EC_Deep1 {
    function d2() public virtual pure returns (uint256) { return 2; }
}

contract EC_Deep3 is EC_Deep2 {
    function d3() public virtual pure returns (uint256) { return 3; }
}

contract EC_Deep4 is EC_Deep3 {
    function d4() public virtual pure returns (uint256) { return 4; }
}

contract EC_Deep5 is EC_Deep4 {
    function d5() public virtual pure returns (uint256) { return 5; }
}

// EC: Deep chain - should detect all 5 ancestors
contract EC_Deep6 is EC_Deep5 {
    function d6() public pure returns (uint256) { return 6; }

    function sumAll() public pure returns (uint256) {
        return d1() + d2() + d3() + d4() + d5() + d6();
    }
}

// =============================================================================
// EDGE CASES - Complex Multiple Inheritance
// =============================================================================

contract EC_ComplexA {
    function a() public virtual pure returns (string memory) { return "A"; }
}

contract EC_ComplexB is EC_ComplexA {
    function b() public virtual pure returns (string memory) { return "B"; }
    function a() public virtual override pure returns (string memory) { return "B.A"; }
}

contract EC_ComplexC is EC_ComplexA {
    function c() public virtual pure returns (string memory) { return "C"; }
    function a() public virtual override pure returns (string memory) { return "C.A"; }
}

contract EC_ComplexD is EC_ComplexB, EC_ComplexC {
    function d() public virtual pure returns (string memory) { return "D"; }
    function a() public override(EC_ComplexB, EC_ComplexC) pure returns (string memory) { return "D.A"; }
}

contract EC_ComplexE is EC_ComplexA {
    function e() public virtual pure returns (string memory) { return "E"; }
}

// EC: Complex graph - inherits from D and E, both of which inherit from A
contract EC_ComplexF is EC_ComplexD, EC_ComplexE {
    function f() public pure returns (string memory) { return "F"; }
    function a() public override(EC_ComplexD, EC_ComplexE) pure returns (string memory) { return "F.A"; }
}

// =============================================================================
// EDGE CASES - Interface Multiple Inheritance
// =============================================================================

interface EC_IA {
    function ia() external view returns (uint256);
}

interface EC_IB {
    function ib() external view returns (uint256);
}

interface EC_IC is EC_IA, EC_IB {
    function ic() external view returns (uint256);
}

interface EC_ID is EC_IC {
    function id() external view returns (uint256);
}

// EC: Contract implementing deeply inherited interface
contract EC_InterfaceChain is EC_ID {
    function ia() external pure override returns (uint256) { return 1; }
    function ib() external pure override returns (uint256) { return 2; }
    function ic() external pure override returns (uint256) { return 3; }
    function id() external pure override returns (uint256) { return 4; }
}

// =============================================================================
// EDGE CASES - Mixed Interface and Contract Inheritance
// =============================================================================

interface EC_IMixed {
    function interfaceMethod() external view returns (uint256);
}

contract EC_MixedBase {
    function contractMethod() public virtual pure returns (uint256) {
        return 100;
    }
}

// EC: Inheriting from both interface and contract
contract EC_MixedDerived is EC_MixedBase, EC_IMixed {
    function interfaceMethod() external pure override returns (uint256) {
        return 1;
    }

    function contractMethod() public pure override returns (uint256) {
        return 200;
    }
}

// =============================================================================
// EDGE CASES - Empty Contracts in Chain
// =============================================================================

contract EC_EmptyBase {
    // Intentionally empty
}

contract EC_EmptyMiddle is EC_EmptyBase {
    // Also empty
}

// EC: Non-empty inheriting from empty chain
contract EC_NonEmpty is EC_EmptyMiddle {
    uint256 public value;

    function setValue(uint256 v) public {
        value = v;
    }
}

// =============================================================================
// EDGE CASES - Overloaded Functions Across Inheritance
// =============================================================================

contract EC_OverloadBase {
    function overloaded(uint256 x) public virtual pure returns (uint256) {
        return x;
    }
}

contract EC_OverloadDerived is EC_OverloadBase {
    // Adding overload, not overriding
    function overloaded(uint256 x, uint256 y) public pure returns (uint256) {
        return x + y;
    }

    // Override the original
    function overloaded(uint256 x) public pure override returns (uint256) {
        return x * 2;
    }
}
