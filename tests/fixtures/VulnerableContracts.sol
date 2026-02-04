// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * Test contract with various vulnerabilities for testing security detectors.
 */

// Vulnerable: Pre-0.8.0 without SafeMath
contract IntegerOverflowVulnerable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] = balances[msg.sender] + msg.value; // Overflow risk
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] = balances[msg.sender] - amount; // Underflow risk
        payable(msg.sender).transfer(amount);
    }

    function multiply(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b; // Overflow risk
    }
}

// Vulnerable: Unchecked send
contract UncheckedSendVulnerable {
    function sendEther(address payable to, uint256 amount) external {
        to.send(amount); // Return value not checked!
    }

    function sendEtherSafe(address payable to, uint256 amount) external {
        require(to.send(amount), "Send failed"); // This is safe
    }
}

// Vulnerable: Unprotected initializer
contract UnprotectedInitializerVulnerable {
    address public owner;
    bool private initialized;

    // Missing initializer modifier!
    function initialize(address _owner) external {
        owner = _owner;
    }

    // Safe version
    function initializeSafe(address _owner) external {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = _owner;
    }
}

// Vulnerable: Price manipulation
interface IUniswapPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract PriceManipulationVulnerable {
    IUniswapPair public pair;

    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return uint256(reserve0) * 1e18 / uint256(reserve1); // Spot price!
    }

    function swapWithPrice(uint256 amount) external {
        uint256 price = getPrice();
        uint256 value = amount * price / 1e18; // Using manipulable price
        // ... do something with value
    }
}

// Vulnerable: Flash loan attack surface
contract FlashLoanVulnerable {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public votingPower;

    // Flash loan callback - can be exploited
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // Vulnerable: modifies state during flash loan
        balances[initiator] = balances[initiator] + amounts[0];
        return true;
    }

    // Governance without flash loan protection
    function vote(uint256 proposalId) external {
        uint256 power = votingPower[msg.sender];
        // Can be exploited with flash loan to temporarily increase voting power
    }
}

// Vulnerable: Storage collision in proxy
contract StorageCollisionProxy {
    address public implementation; // Slot 0 - may collide!
    address public admin;          // Slot 1 - may collide!

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _delegate(implementation);
    }
}
