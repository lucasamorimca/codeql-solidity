// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test file for inter-procedural analysis infrastructure.
 * Tests:
 * - Call resolution (internal, inherited, super, this)
 * - Inheritance graph
 * - External call detection
 * - Modifier analysis
 * - Taint tracking
 */

// =============================================================================
// BASE CONTRACTS FOR INHERITANCE TESTING
// =============================================================================

contract BaseA {
    uint256 public valueA;

    function setValueA(uint256 val) public virtual {
        valueA = val;
    }

    function getValueA() public view returns (uint256) {
        return valueA;
    }

    modifier onlyPositive(uint256 val) {
        require(val > 0, "Must be positive");
        _;
    }
}

contract BaseB is BaseA {
    uint256 public valueB;

    function setValueB(uint256 val) public {
        valueB = val;
    }

    // Override parent function
    function setValueA(uint256 val) public virtual override {
        valueA = val * 2;  // Different behavior
    }

    function callParentSetValueA(uint256 val) public {
        // super call - should resolve to BaseA.setValueA
        super.setValueA(val);
    }
}

contract BaseC is BaseB {
    uint256 public valueC;

    // Further override
    function setValueA(uint256 val) public override {
        valueA = val * 3;
    }

    function callSuperSetValueA(uint256 val) public {
        // Should resolve to BaseB.setValueA
        super.setValueA(val);
    }

    // Internal call testing
    function internalCallTest(uint256 val) public {
        setValueB(val);  // Should resolve to BaseB.setValueB
        setValueA(val);  // Should resolve to BaseC.setValueA (most derived)
    }
}

// =============================================================================
// INTERFACE AND EXTERNAL CALL TESTING
// =============================================================================

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
}

contract ExternalCallTest {
    IToken public token;
    IVault public vault;
    address public owner;

    constructor(address _token, address _vault) {
        token = IToken(_token);
        vault = IVault(_vault);
        owner = msg.sender;
    }

    // External call through interface - should be detected
    function transferTokens(address to, uint256 amount) external {
        token.transfer(to, amount);  // External call
    }

    // Low-level call - should be detected as external
    function lowLevelCall(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);  // Low-level call
        require(success, "Call failed");
    }

    // Delegatecall - high risk external call
    function delegateCall(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);  // Delegatecall
        require(success, "Delegatecall failed");
    }

    // Staticcall - read-only external call
    function staticCallTest(address target, bytes calldata data) external view returns (bytes memory) {
        (bool success, bytes memory result) = target.staticcall(data);
        require(success, "Staticcall failed");
        return result;
    }

    // this.func() - external self-call
    function externalSelfCall() external {
        this.transferTokens(owner, 100);  // this. call
    }

    // Value transfer
    function sendEther(address payable to) external payable {
        to.transfer(msg.value);  // Ether transfer
    }
}

// =============================================================================
// MODIFIER ANALYSIS TESTING
// =============================================================================

contract ModifierTest {
    address public owner;
    bool private locked;
    uint256 public maxAmount;

    constructor() {
        owner = msg.sender;
        maxAmount = 1000;
    }

    // Access control modifier - checks msg.sender
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Reentrancy guard modifier
    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    // Parameter validation modifier
    modifier validAmount(uint256 amount) {
        require(amount > 0, "Amount must be positive");
        require(amount <= maxAmount, "Amount too large");
        _;
    }

    // Modifier with overflow check pattern
    modifier checkOverflow(uint256 a, uint256 b) {
        require(a <= type(uint256).max - b, "Overflow");
        _;
    }

    // Function with multiple modifiers
    function protectedFunction(uint256 amount)
        external
        onlyOwner
        nonReentrant
        validAmount(amount)
    {
        // Protected by modifiers
    }

    // Function with overflow check modifier
    function safeAdd(uint256 a, uint256 b)
        external
        pure
        checkOverflow(a, b)
        returns (uint256)
    {
        return a + b;
    }

    // Change owner - access control
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}

// =============================================================================
// TAINT TRACKING TESTING
// =============================================================================

contract TaintTest {
    mapping(address => uint256) public balances;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    // Taint from msg.sender
    function msgSenderTaint() external {
        // msg.sender is taint source
        balances[msg.sender] = 100;  // Taint flows to mapping key
    }

    // Taint from msg.value
    function msgValueTaint() external payable {
        // msg.value is taint source
        uint256 amount = msg.value;  // Taint flows to local
        balances[msg.sender] = amount;  // Taint flows to state
    }

    // Taint from external function parameter
    function parameterTaint(uint256 userInput) external {
        // userInput is taint source (external parameter)
        uint256 result = userInput * 2;  // Taint propagates through arithmetic
        balances[msg.sender] = result;
    }

    // Taint from external call result
    function externalCallTaint(address token) external {
        // External call result is taint source
        (bool success, bytes memory data) = token.call(abi.encodeWithSignature("balanceOf(address)", msg.sender));
        require(success);
        // data is tainted
    }

    // Taint to sensitive sink (selfdestruct)
    function selfdestructSink(address payable beneficiary) external {
        require(msg.sender == admin);
        selfdestruct(beneficiary);  // beneficiary is sink
    }

    // Taint barrier - require validation
    function taintBarrier(uint256 input) external {
        require(input < 1000, "Too large");  // Barrier
        // input is sanitized after require
        balances[msg.sender] = input;
    }

    // Taint through ABI encoding
    function abiEncodeTaint(uint256 a, uint256 b) external pure returns (bytes memory) {
        // Taint propagates through abi.encode
        return abi.encode(a, b);
    }

    // Taint through hash function
    function hashTaint(bytes memory data) external pure returns (bytes32) {
        // Taint propagates through keccak256
        return keccak256(data);
    }
}

// =============================================================================
// INTER-PROCEDURAL FLOW TESTING
// =============================================================================

contract InterProceduralFlowTest {
    uint256 public value;
    address public target;

    function helper(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }

    function anotherHelper(uint256 y) private pure returns (uint256) {
        return y + 1;
    }

    // Cross-function flow: argument -> parameter
    function caller(uint256 input) external {
        uint256 result = helper(input);  // Flow: input -> x -> result
        value = result;
    }

    // Multiple call chain
    function chainedCalls(uint256 input) external {
        uint256 doubled = helper(input);     // input -> doubled
        uint256 plusOne = anotherHelper(doubled);  // doubled -> plusOne
        value = plusOne;
    }

    // Flow through inherited function
    function inheritedFlow(uint256 input) external {
        // Would call inherited function
        value = input;
    }
}

// =============================================================================
// REENTRANCY PATTERN TESTING
// =============================================================================

interface ICallback {
    function callback() external;
}

contract ReentrancyTest {
    mapping(address => uint256) public balances;
    bool private locked;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: state change after external call
    function vulnerableWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        // External call BEFORE state change - VULNERABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        // State change AFTER external call
        balances[msg.sender] -= amount;
    }

    // SAFE: state change before external call
    function safeWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);

        // State change BEFORE external call
        balances[msg.sender] -= amount;

        // External call after state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }

    // SAFE: with reentrancy guard
    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    function guardedWithdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] -= amount;  // Safe due to guard
    }
}

// =============================================================================
// COMPLEX INHERITANCE - DIAMOND PATTERN
// =============================================================================

contract DiamondA {
    function foo() public virtual pure returns (string memory) {
        return "A";
    }
}

contract DiamondB is DiamondA {
    function foo() public virtual override pure returns (string memory) {
        return "B";
    }
}

contract DiamondC is DiamondA {
    function foo() public virtual override pure returns (string memory) {
        return "C";
    }
}

// Diamond inheritance - B and C both inherit from A
contract DiamondD is DiamondB, DiamondC {
    // Must override since both B and C override foo
    function foo() public override(DiamondB, DiamondC) pure returns (string memory) {
        return "D";
    }

    function callBFoo() public pure returns (string memory) {
        return DiamondB.foo();  // Explicit base call
    }

    function callCFoo() public pure returns (string memory) {
        return DiamondC.foo();  // Explicit base call
    }
}
