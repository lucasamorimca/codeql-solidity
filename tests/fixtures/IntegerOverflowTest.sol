// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * Test cases for IntegerOverflow.ql detector
 * Uses Solidity <0.8.0 where overflow checks are not automatic
 */

// VULNERABLE: All arithmetic without SafeMath
contract IntegerOverflowVulnerable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // VULNERABLE: Addition overflow
    function deposit() external payable {
        balances[msg.sender] = balances[msg.sender] + msg.value;
        totalSupply = totalSupply + msg.value;
    }

    // VULNERABLE: Subtraction underflow
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] = balances[msg.sender] - amount;
        totalSupply = totalSupply - amount;
        payable(msg.sender).transfer(amount);
    }

    // VULNERABLE: Multiplication overflow
    function multiply(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }

    // VULNERABLE: Exponentiation overflow
    function power(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ** exp;
    }

    // VULNERABLE: Complex expression
    function calculateReward(uint256 stake, uint256 rate, uint256 time) external pure returns (uint256) {
        return stake * rate * time / 1e18;
    }
}

// VULNERABLE: Token with overflow issues
contract VulnerableToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    string public name = "Vulnerable Token";

    // VULNERABLE: mint overflow
    function mint(address to, uint256 amount) external {
        balanceOf[to] = balanceOf[to] + amount;
        totalSupply = totalSupply + amount;
    }

    // VULNERABLE: transfer underflow/overflow
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] = balanceOf[msg.sender] - amount;
        balanceOf[to] = balanceOf[to] + amount;
        return true;
    }

    // VULNERABLE: transferFrom with multiple operations
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] = allowance[from][msg.sender] - amount;
        balanceOf[from] = balanceOf[from] - amount;
        balanceOf[to] = balanceOf[to] + amount;
        return true;
    }

    // VULNERABLE: approve doesn't check for overflow in allowance
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

// SAFE: Using SafeMath library
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }
}

contract SafeMathToken {
    using SafeMath for uint256;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    // SAFE: Uses SafeMath.add
    function mint(address to, uint256 amount) external {
        balanceOf[to] = balanceOf[to].add(amount);
        totalSupply = totalSupply.add(amount);
    }

    // SAFE: Uses SafeMath.sub
    function burn(uint256 amount) external {
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(amount);
        totalSupply = totalSupply.sub(amount);
    }

    // SAFE: Uses SafeMath.mul
    function calculateFee(uint256 amount, uint256 feeRate) external pure returns (uint256) {
        return amount.mul(feeRate);
    }
}

// SAFE: Constant expressions (compile-time checked)
contract ConstantsSafe {
    // SAFE: Constants are checked at compile time
    uint256 public constant MAX_SUPPLY = 1000000 * 10**18;
    uint256 public constant FEE_DENOMINATOR = 10000;
    uint256 public constant MAX_FEE = 1000; // 10%

    function getMaxFeeAmount(uint256 amount) external pure returns (uint256) {
        // SAFE: constant * variable is still risky, but constant/constant is safe
        return MAX_FEE * amount / FEE_DENOMINATOR;
    }
}

// VULNERABLE: DeFi operations
contract VulnerableDeFi {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public shares;
    uint256 public totalDeposits;
    uint256 public totalShares;

    // VULNERABLE: share calculation overflow
    function deposit(uint256 amount) external {
        uint256 sharesToMint;
        if (totalShares == 0) {
            sharesToMint = amount;
        } else {
            sharesToMint = amount * totalShares / totalDeposits;
        }

        deposits[msg.sender] = deposits[msg.sender] + amount;
        shares[msg.sender] = shares[msg.sender] + sharesToMint;
        totalDeposits = totalDeposits + amount;
        totalShares = totalShares + sharesToMint;
    }

    // VULNERABLE: withdrawal calculation
    function withdraw(uint256 shareAmount) external {
        uint256 amountToWithdraw = shareAmount * totalDeposits / totalShares;

        shares[msg.sender] = shares[msg.sender] - shareAmount;
        deposits[msg.sender] = deposits[msg.sender] - amountToWithdraw;
        totalShares = totalShares - shareAmount;
        totalDeposits = totalDeposits - amountToWithdraw;
    }

    // VULNERABLE: interest calculation
    function calculateInterest(uint256 principal, uint256 rate, uint256 time) external pure returns (uint256) {
        return principal * rate * time / 365 / 1e18;
    }
}

// VULNERABLE: Batch operations
contract BatchOperations {
    mapping(address => uint256) public balances;

    // VULNERABLE: Multiple additions in loop
    function batchDeposit(address[] calldata users, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = balances[users[i]] + amounts[i];
        }
    }

    // VULNERABLE: Sum calculation
    function sumAmounts(uint256[] calldata amounts) external pure returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            total = total + amounts[i];
        }
        return total;
    }
}
