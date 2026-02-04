// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test cases for UncheckedMath.ql detector
 * Tests arithmetic in unchecked blocks with critical variables
 */

// VULNERABLE: Unchecked arithmetic with balance variables
contract UncheckedMathVulnerable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // VULNERABLE: balance arithmetic in unchecked block
    function unsafeTransfer(address to, uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;  // VULNERABLE: balance underflow
            balances[to] += amount;          // VULNERABLE: balance overflow
        }
    }

    // VULNERABLE: totalSupply in unchecked
    function unsafeMint(address to, uint256 amount) external {
        unchecked {
            totalSupply += amount;           // VULNERABLE: supply overflow
            balances[to] += amount;          // VULNERABLE: balance overflow
        }
    }

    // VULNERABLE: amount parameter in unchecked
    function unsafeDeposit(uint256 amount) external {
        unchecked {
            uint256 shares = amount * 1e18 / totalSupply;  // VULNERABLE
            balances[msg.sender] += shares;
        }
    }
}

// VULNERABLE: Unchecked in token functions
contract UncheckedTokenOperations {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;

    // VULNERABLE: transfer function with unchecked
    function transfer(address to, uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }

    // VULNERABLE: withdraw with unchecked balance
    function withdraw(uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;
        }
        payable(msg.sender).transfer(amount);
    }

    // VULNERABLE: mint with unchecked
    function mint(address to, uint256 amount) external {
        unchecked {
            balances[to] += amount;
        }
    }

    // VULNERABLE: burn with unchecked
    function burn(uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;
        }
    }
}

// SAFE: Unchecked with non-critical variables
contract UncheckedMathSafe {
    uint256 public counter;
    mapping(address => uint256) public balances;

    // SAFE: Loop counter in unchecked (intentional gas optimization)
    function safeLoop(uint256 iterations) external {
        for (uint256 i = 0; i < iterations;) {
            unchecked {
                ++i;  // SAFE: just a counter
            }
        }
    }

    // SAFE: Index calculation in unchecked
    function safeIndex(uint256[] calldata arr, uint256 start) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = start; i < arr.length;) {
            sum += arr[i];
            unchecked {
                ++i;  // SAFE: just incrementing index
            }
        }
        return sum;
    }

    // SAFE: Balance operations outside unchecked
    function safeTransfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;  // SAFE: checked by default in 0.8+
        balances[to] += amount;
    }
}

// VULNERABLE: DeFi-specific unchecked operations
contract UncheckedDeFi {
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public reserves;
    uint256 public totalStake;

    // VULNERABLE: stake operations in unchecked
    function stake(uint256 amount) external {
        unchecked {
            stakes[msg.sender] += amount;   // VULNERABLE
            totalStake += amount;            // VULNERABLE
        }
    }

    // VULNERABLE: reserve manipulation in unchecked
    function addReserve(uint256 amount) external {
        unchecked {
            reserves[msg.sender] += amount;  // VULNERABLE
        }
    }

    // VULNERABLE: share calculation in unchecked
    function calculateShares(uint256 amount, uint256 total) external pure returns (uint256) {
        unchecked {
            return amount * 1e18 / total;  // VULNERABLE: amount in calculation
        }
    }
}
