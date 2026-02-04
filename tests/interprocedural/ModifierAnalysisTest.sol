// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test file for Modifier Analysis
 *
 * TRUE POSITIVES (TP_): Modifiers that SHOULD be detected and resolved
 * FALSE POSITIVES (FP_): Things that should NOT be detected as modifiers
 * EDGE CASES (EC_): Complex modifier scenarios
 */

// =============================================================================
// TRUE POSITIVES - Access Control Modifiers
// =============================================================================

contract TP_AccessControl {
    address public owner;
    mapping(address => bool) public admins;
    mapping(address => bool) public minters;

    constructor() {
        owner = msg.sender;
    }

    // TP: onlyOwner modifier - classic access control
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // TP: onlyAdmin modifier - role-based access control
    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    // TP: onlyMinter modifier - another role
    modifier onlyMinter() {
        require(minters[msg.sender], "Not minter");
        _;
    }

    // TP: Function with onlyOwner - should detect access control
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    // TP: Function with onlyAdmin - should detect access control
    function addMinter(address minter) public onlyAdmin {
        minters[minter] = true;
    }

    // TP: Function with multiple access control modifiers
    function criticalOperation() public onlyOwner onlyAdmin {
        // Critical operation
    }
}

// =============================================================================
// TRUE POSITIVES - Reentrancy Guards
// =============================================================================

contract TP_ReentrancyGuards {
    bool private locked;
    uint256 private status;

    // TP: Classic reentrancy guard
    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    // TP: OpenZeppelin-style reentrancy guard
    modifier noReentrancy() {
        require(status != 2, "Reentrant");
        status = 2;
        _;
        status = 1;
    }

    // TP: Custom lock modifier (should be detected as reentrancy guard)
    modifier lock() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    // TP: Function with reentrancy guard
    function withdraw(uint256 amount) public nonReentrant {
        payable(msg.sender).transfer(amount);
    }

    // TP: Function with custom lock
    function safeWithdraw() public lock {
        payable(msg.sender).transfer(1 ether);
    }
}

// =============================================================================
// TRUE POSITIVES - Inherited Modifiers
// =============================================================================

contract TP_BaseWithModifiers {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // TP: Modifier in base contract
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    // TP: Another base modifier
    modifier whenActive() {
        require(true); // Simplified
        _;
    }
}

contract TP_DerivedWithModifiers is TP_BaseWithModifiers {
    // TP: Using inherited modifier - should resolve to base
    function inheritedModifierFunc() public onlyOwner {
        // Should resolve modifier to base contract
    }

    // TP: Using multiple inherited modifiers
    function multipleInheritedModifiers() public onlyOwner whenActive {
        // Both should resolve
    }
}

contract TP_OverrideModifier is TP_BaseWithModifiers {
    // TP: Override modifier
    modifier onlyOwner() override {
        require(msg.sender == owner, "Custom: Not owner");
        _;
    }

    // TP: Should resolve to overridden modifier
    function useOverriddenModifier() public onlyOwner {
        // Should resolve to THIS contract's modifier
    }
}

// =============================================================================
// TRUE POSITIVES - Parameterized Modifiers
// =============================================================================

contract TP_ParameterizedModifiers {
    mapping(bytes32 => bool) public roles;
    mapping(address => mapping(bytes32 => bool)) public hasRole;

    // TP: Modifier with role parameter
    modifier onlyRole(bytes32 role) {
        require(hasRole[msg.sender][role], "Missing role");
        _;
    }

    // TP: Modifier with amount validation
    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be positive");
        require(amount <= 1000 ether, "Amount too large");
        _;
    }

    // TP: Modifier with address validation
    modifier validAddress(address addr) {
        require(addr != address(0), "Invalid address");
        _;
    }

    // TP: Function using parameterized modifier
    function roleProtectedFunc() public onlyRole(keccak256("ADMIN")) {
        // Role protected
    }

    // TP: Function with amount validation
    function deposit(uint256 amount) public validAmount(amount) {
        // Amount validated
    }

    // TP: Multiple parameterized modifiers
    function transferTo(address to, uint256 amount) public validAddress(to) validAmount(amount) {
        // Both address and amount validated
    }
}

// =============================================================================
// TRUE POSITIVES - State Validation Modifiers
// =============================================================================

contract TP_StateModifiers {
    bool public paused;
    bool public initialized;
    uint256 public deadline;

    // TP: Pause modifier
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    // TP: Pause modifier (inverse)
    modifier whenPaused() {
        require(paused, "Contract is not paused");
        _;
    }

    // TP: Initialization check
    modifier initializer() {
        require(!initialized, "Already initialized");
        _;
        initialized = true;
    }

    // TP: Deadline check
    modifier beforeDeadline() {
        require(block.timestamp < deadline, "Past deadline");
        _;
    }

    // TP: Function with pause check
    function normalOperation() public whenNotPaused {
        // Only works when not paused
    }

    // TP: Function with multiple state checks
    function timeSensitiveOperation() public whenNotPaused beforeDeadline {
        // Requires not paused AND before deadline
    }
}

// =============================================================================
// FALSE POSITIVES - Not Access Control or Reentrancy
// =============================================================================

contract FP_NotAccessControl {
    uint256 public counter;

    // FP: This is NOT access control - just logging
    modifier withLog() {
        emit FunctionCalled();
        _;
    }

    // FP: This is NOT access control - just incrementing counter
    modifier incrementCounter() {
        counter++;
        _;
    }

    // FP: Gas optimization modifier - not security related
    modifier optimized() {
        _;
    }

    event FunctionCalled();

    // FP: Function with non-access-control modifier
    function loggedFunction() public withLog {
        // Not access controlled
    }
}

contract FP_NotModifiers {
    // FP: Regular function, not a modifier
    function onlyOwner() public pure returns (bool) {
        return true;
    }

    // FP: Regular function with "modifier-like" name
    function nonReentrant() internal pure returns (bool) {
        return false;
    }

    // FP: State variable with modifier-like name
    bool public whenPaused;

    // FP: Event with modifier-like name
    event OnlyOwnerCalled(address caller);
}

// =============================================================================
// EDGE CASES - Complex Modifier Patterns
// =============================================================================

// EC: Modifier in abstract contract
abstract contract EC_AbstractWithModifier {
    address public owner;

    modifier onlyOwner() virtual {
        require(msg.sender == owner);
        _;
    }

    // EC: Function using modifier in abstract contract
    function abstractProtectedFunc() public virtual onlyOwner {
        // Override this
    }
}

contract EC_ConcreteFromAbstract is EC_AbstractWithModifier {
    constructor() {
        owner = msg.sender;
    }

    // EC: Using inherited abstract modifier
    function concreteFunc() public onlyOwner {
        // Should resolve to EC_AbstractWithModifier.onlyOwner
    }
}

// EC: Multiple inheritance with modifiers
contract EC_MultiBase1 {
    modifier mod1() {
        require(true);
        _;
    }
}

contract EC_MultiBase2 {
    modifier mod2() {
        require(true);
        _;
    }
}

contract EC_MultiDerived is EC_MultiBase1, EC_MultiBase2 {
    // EC: Using modifiers from both parents
    function useMultipleParentModifiers() public mod1 mod2 {
        // Both should resolve
    }
}

// EC: Diamond inheritance with modifiers
contract EC_DiamondTop {
    address public owner;

    modifier onlyOwner() virtual {
        require(msg.sender == owner);
        _;
    }
}

contract EC_DiamondLeft is EC_DiamondTop {
    modifier onlyOwner() virtual override {
        require(msg.sender == owner, "Left: Not owner");
        _;
    }
}

contract EC_DiamondRight is EC_DiamondTop {
    modifier onlyOwner() virtual override {
        require(msg.sender == owner, "Right: Not owner");
        _;
    }
}

contract EC_DiamondBottom is EC_DiamondLeft, EC_DiamondRight {
    // EC: Must override to resolve diamond
    modifier onlyOwner() override(EC_DiamondLeft, EC_DiamondRight) {
        require(msg.sender == owner, "Bottom: Not owner");
        _;
    }

    // EC: Uses the final override
    function diamondProtectedFunc() public onlyOwner {
        // Should resolve to EC_DiamondBottom.onlyOwner
    }
}

// EC: Modifier with complex logic
contract EC_ComplexModifier {
    address public owner;
    mapping(address => bool) public whitelist;
    bool public paused;

    // EC: Modifier with multiple conditions
    modifier complexAccess() {
        require(!paused, "Paused");
        require(msg.sender == owner || whitelist[msg.sender], "No access");
        _;
        // Post-condition
        emit AccessGranted(msg.sender);
    }

    event AccessGranted(address user);

    // EC: Using complex modifier
    function complexProtectedFunc() public complexAccess {
        // Complex access control
    }
}

// EC: Modifier calling internal function
contract EC_ModifierWithCall {
    mapping(address => bool) public authorized;

    function checkAuth(address user) internal view returns (bool) {
        return authorized[user];
    }

    // EC: Modifier that calls internal function
    modifier onlyAuthorized() {
        require(checkAuth(msg.sender), "Not authorized");
        _;
    }

    // EC: Using modifier that calls function
    function authorizedFunc() public onlyAuthorized {
        // Should detect as access control
    }
}

// EC: Nested modifiers (modifier calling another modifier's pattern)
contract EC_NestedPatterns {
    bool private locked;
    address public owner;

    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    // EC: Function with both types of modifiers
    function ownerOnlyWithGuard() public onlyOwner nonReentrant {
        // Both access control AND reentrancy guard
    }
}

// EC: Modifier in library (not directly applicable but good to test)
library EC_LibraryWithHelper {
    function checkOwner(address owner) internal view {
        require(msg.sender == owner);
    }
}

contract EC_UsingLibraryInModifier {
    address public owner;

    // EC: Modifier using library function
    modifier ownerCheck() {
        EC_LibraryWithHelper.checkOwner(owner);
        _;
    }

    function libraryModifierFunc() public ownerCheck {
        // Uses library in modifier
    }
}

// EC: Placeholder position variations
contract EC_PlaceholderPositions {
    event Before();
    event After();

    // EC: Placeholder at start
    modifier placeholderFirst() {
        _;
        emit After();
    }

    // EC: Placeholder at end
    modifier placeholderLast() {
        emit Before();
        _;
    }

    // EC: Multiple placeholders (unusual but valid)
    // Note: Only one placeholder is typically used, this tests unusual patterns

    // EC: Placeholder in conditional
    modifier conditionalPlaceholder(bool condition) {
        if (condition) {
            _;
        } else {
            revert("Condition not met");
        }
    }

    function useConditionalModifier() public conditionalPlaceholder(true) {
        // Conditional execution
    }
}

// EC: View and pure function modifiers
contract EC_ViewPureModifiers {
    uint256 public value;

    // EC: Modifier used on view function
    modifier viewSafe() {
        // Can't modify state in view modifier
        _;
    }

    // EC: Modifier used on pure function
    modifier pureSafe() {
        _;
    }

    function viewFunc() public view viewSafe returns (uint256) {
        return value;
    }

    function pureFunc(uint256 x) public pure pureSafe returns (uint256) {
        return x * 2;
    }
}

// EC: Empty modifier body
contract EC_EmptyModifier {
    // EC: Modifier with only placeholder
    modifier emptyMod() {
        _;
    }

    function useEmptyMod() public emptyMod {
        // Does nothing special
    }
}

// EC: Modifier with return values in require
contract EC_ModifierWithFunctionCalls {
    function isAllowed() internal pure returns (bool) {
        return true;
    }

    function getAllowance() internal pure returns (uint256) {
        return 100;
    }

    // EC: Modifier calling view functions
    modifier checkAllowance() {
        require(isAllowed(), "Not allowed");
        require(getAllowance() > 0, "No allowance");
        _;
    }

    function allowedFunc() public checkAllowance {
        // Uses modifier with function calls
    }
}
