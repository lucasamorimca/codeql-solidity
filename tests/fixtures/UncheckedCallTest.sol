// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test cases for UncheckedCall.ql and UncheckedSend.ql detectors
 */

// VULNERABLE: Unchecked low-level calls
contract UncheckedCallVulnerable {
    // VULNERABLE: call() return value not checked
    function unsafeCall(address target, bytes calldata data) external {
        target.call(data);
    }

    // VULNERABLE: delegatecall() return value not checked
    function unsafeDelegatecall(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    // VULNERABLE: staticcall() return value not checked
    function unsafeStaticcall(address target, bytes calldata data) external view {
        target.staticcall(data);
    }

    // VULNERABLE: send() return value not checked
    function unsafeSend(address payable to, uint256 amount) external {
        to.send(amount);
    }
}

// SAFE: Properly checked low-level calls
contract UncheckedCallSafe {
    // SAFE: call() with require check
    function safeCallRequire(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }

    // SAFE: call() with if check
    function safeCallIf(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        if (!success) {
            revert("Call failed");
        }
    }

    // SAFE: send() with require check
    function safeSendRequire(address payable to, uint256 amount) external {
        require(to.send(amount), "Send failed");
    }

    // SAFE: send() with if check
    function safeSendIf(address payable to, uint256 amount) external {
        bool sent = to.send(amount);
        if (!sent) {
            revert("Send failed");
        }
    }

    // SAFE: call() assigned to tuple (assumes checked later)
    function safeCallTuple(address target, bytes calldata data) external returns (bool) {
        (bool success, bytes memory result) = target.call(data);
        return success;
    }

    // SAFE: delegatecall() with assert
    function safeDelegatecallAssert(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        assert(success);
    }
}

// VULNERABLE: Mixed - some checked, some not
contract UncheckedCallMixed {
    // VULNERABLE: First call unchecked
    function mixedCalls(address target1, address target2, bytes calldata data) external {
        target1.call(data);  // VULNERABLE

        (bool success, ) = target2.call(data);
        require(success);  // SAFE
    }

    // VULNERABLE: Nested unchecked call
    function nestedUnchecked(address target, bytes calldata data) external {
        if (true) {
            target.delegatecall(data);  // VULNERABLE
        }
    }
}

// SAFE: Using transfer() instead (reverts on failure)
contract UseTransfer {
    function safeTransfer(address payable to, uint256 amount) external {
        to.transfer(amount);  // SAFE: transfer() reverts on failure
    }
}
