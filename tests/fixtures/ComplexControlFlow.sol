// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ComplexControlFlow
 * @dev Contract with various control flow patterns for testing CFG
 */
contract ComplexControlFlow {
    uint256 public counter;
    mapping(address => uint256) public balances;

    error InsufficientFunds(uint256 available, uint256 required);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    // Simple if-else
    function simpleIf(uint256 x) public pure returns (uint256) {
        if (x > 10) {
            return x * 2;
        } else {
            return x + 1;
        }
    }

    // Nested if-else
    function nestedIf(uint256 x, uint256 y) public pure returns (uint256) {
        if (x > 10) {
            if (y > 5) {
                return x + y;
            } else {
                return x - y;
            }
        } else {
            if (y > 5) {
                return y - x;
            }
            return 0;
        }
    }

    // For loop
    function forLoop(uint256 n) public pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            sum += i;
        }
        return sum;
    }

    // While loop
    function whileLoop(uint256 n) public pure returns (uint256) {
        uint256 sum = 0;
        uint256 i = 0;
        while (i < n) {
            sum += i;
            i++;
        }
        return sum;
    }

    // Do-while loop
    function doWhileLoop(uint256 n) public pure returns (uint256) {
        uint256 sum = 0;
        uint256 i = 0;
        do {
            sum += i;
            i++;
        } while (i < n);
        return sum;
    }

    // Break and continue
    function breakContinue(uint256 n) public pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            if (i == 5) {
                continue;
            }
            if (i == 10) {
                break;
            }
            sum += i;
        }
        return sum;
    }

    // Try-catch
    function tryCatch(address target) public returns (bool) {
        try IERC20(target).transfer(msg.sender, 100) returns (bool success) {
            return success;
        } catch Error(string memory reason) {
            emit Transfer(address(0), msg.sender, 0);
            return false;
        } catch {
            return false;
        }
    }

    // Nested loops
    function nestedLoops(uint256 n, uint256 m) public pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j < m; j++) {
                sum += i * j;
            }
        }
        return sum;
    }

    // Early return
    function earlyReturn(uint256 x) public pure returns (uint256) {
        if (x == 0) {
            return 0;
        }

        uint256 result = x;
        for (uint256 i = 1; i < x; i++) {
            result *= i;
            if (result > 1000000) {
                return result;
            }
        }
        return result;
    }

    // Revert
    function withdraw(uint256 amount) public {
        if (balances[msg.sender] < amount) {
            revert InsufficientFunds(balances[msg.sender], amount);
        }
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Unchecked block
    function uncheckedMath(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            return a + b;
        }
    }

    // Assembly
    function assemblyControl(uint256 x) public pure returns (uint256 result) {
        assembly {
            switch x
            case 0 { result := 0 }
            case 1 { result := 1 }
            default { result := mul(x, x) }
        }
    }

    // Complex condition
    function complexCondition(uint256 a, uint256 b, uint256 c) public pure returns (bool) {
        return (a > 0 && b > 0) || (c > 0 && a + b > c);
    }

    // Ternary operator
    function ternary(uint256 x) public pure returns (uint256) {
        return x > 10 ? x * 2 : x + 1;
    }

    // Multiple returns
    function multipleReturns(uint256 x) public pure returns (uint256, uint256) {
        if (x > 100) {
            return (x, x * 2);
        }
        return (x + 1, x + 2);
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    fallback() external payable {
        counter++;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
