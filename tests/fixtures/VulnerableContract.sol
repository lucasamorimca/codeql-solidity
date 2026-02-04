// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * A contract with various vulnerabilities for testing DataFlow.
 */
contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    bool private locked;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability: Reentrancy - external call before state update
    function withdrawReentrant(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call (CEI violation)
        balances[msg.sender] -= amount;
    }

    // Safe: Follows CEI pattern
    function withdrawSafe(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // State update before external call
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // Vulnerability: tx.origin authentication
    function txOriginAuth() public {
        require(tx.origin == owner, "Not owner");
        // Critical operation
        owner = msg.sender;
    }

    // Vulnerability: Unchecked call return value
    function uncheckedCall(address target, bytes memory data) public {
        target.call(data);  // Return value not checked
    }

    // Vulnerability: User-controlled delegatecall target
    function vulnerableDelegatecall(address target, bytes memory data) public {
        // User-controlled target is dangerous
        target.delegatecall(data);
    }

    // Vulnerability: User-controlled selfdestruct
    function vulnerableSelfdestruct(address payable recipient) public {
        // Any user can destroy the contract
        selfdestruct(recipient);
    }

    // Safe: Protected selfdestruct
    function protectedSelfdestruct(address payable recipient) public {
        require(msg.sender == owner, "Not owner");
        selfdestruct(recipient);
    }

    // Vulnerability: Integer overflow (pre-0.8.0 pattern)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        // In pre-0.8.0, this could overflow
        return a + b;
    }

    // Vulnerability: Missing access control
    function setOwner(address newOwner) public {
        // Anyone can call this!
        owner = newOwner;
    }

    // Safe: With access control
    function setOwnerSafe(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    // Vulnerability: Tainted array index
    function unsafeArrayAccess(uint256[] storage arr, uint256 index) internal view returns (uint256) {
        // index from user input could be out of bounds
        return arr[index];
    }

    // Data flow test: Track user input through multiple functions
    function processInput(uint256 userInput) public pure returns (uint256) {
        uint256 processed = userInput * 2;
        uint256 result = transform(processed);
        return result;
    }

    function transform(uint256 value) internal pure returns (uint256) {
        return value + 100;
    }

    // Taint test: msg.sender flows to external call
    function forwardToSender() public {
        address target = msg.sender;  // Tainted source
        target.call("");  // Tainted sink
    }

    // Taint test: parameter flows to critical state
    function updateBalance(address user, uint256 amount) public {
        // user and amount are tainted parameters
        balances[user] = amount;  // Sink: critical state modification
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * Contract demonstrating flash loan vulnerability patterns.
 */
contract FlashLoanVulnerable {
    mapping(address => uint256) public balances;

    // Vulnerability: Price manipulation via flash loan
    function getPrice() public view returns (uint256) {
        // Using contract balance as price oracle (vulnerable to manipulation)
        return address(this).balance;
    }

    function vulnerableSwap(uint256 amount) public {
        uint256 price = getPrice();  // Can be manipulated
        uint256 output = amount * price;
        // ... swap logic
    }
}
