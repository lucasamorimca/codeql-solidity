// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test file for External Call Detection
 *
 * TRUE POSITIVES (TP_): External calls that SHOULD be detected
 * FALSE POSITIVES (FP_): Internal calls that should NOT be detected as external
 * EDGE CASES (EC_): Boundary conditions and tricky scenarios
 */

// =============================================================================
// Interfaces for Testing
// =============================================================================

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IVault {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function getBalance() external view returns (uint256);
}

interface ICallback {
    function callback(bytes calldata data) external;
}

// =============================================================================
// TRUE POSITIVES - Low-Level Calls
// =============================================================================

contract TP_LowLevelCalls {
    // TP: Basic call() - should be detected as external
    function basicCall(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);  // TP: Low-level call
        require(success, "Call failed");
    }

    // TP: call() with value - should be detected
    function callWithValue(address target, bytes calldata data) external payable {
        (bool success, ) = target.call{value: msg.value}(data);  // TP: Low-level call with value
        require(success, "Call failed");
    }

    // TP: call() with gas limit - should be detected
    function callWithGas(address target, bytes calldata data) external {
        (bool success, ) = target.call{gas: 100000}(data);  // TP: Low-level call with gas
        require(success, "Call failed");
    }

    // TP: call() with both value and gas - should be detected
    function callWithBoth(address target, bytes calldata data) external payable {
        (bool success, ) = target.call{value: msg.value, gas: 100000}(data);  // TP
        require(success, "Call failed");
    }

    // TP: Capturing return data - should be detected
    function callWithReturn(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory returnData) = target.call(data);  // TP
        require(success, "Call failed");
        return returnData;
    }
}

contract TP_Delegatecall {
    // TP: Basic delegatecall - should be detected (high risk)
    function basicDelegatecall(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);  // TP: Delegatecall
        require(success, "Delegatecall failed");
    }

    // TP: delegatecall with gas - should be detected
    function delegatecallWithGas(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall{gas: 50000}(data);  // TP: Delegatecall
        require(success, "Delegatecall failed");
    }

    // TP: delegatecall in a loop - dangerous pattern
    function delegatecallLoop(address[] calldata targets, bytes calldata data) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].delegatecall(data);  // TP: Delegatecall in loop
            require(success);
        }
    }
}

contract TP_Staticcall {
    // TP: Basic staticcall - should be detected
    function basicStaticcall(address target, bytes calldata data) external view returns (bytes memory) {
        (bool success, bytes memory returnData) = target.staticcall(data);  // TP: Staticcall
        require(success, "Staticcall failed");
        return returnData;
    }

    // TP: staticcall with gas - should be detected
    function staticcallWithGas(address target, bytes calldata data) external view returns (bytes memory) {
        (bool success, bytes memory returnData) = target.staticcall{gas: 30000}(data);  // TP
        require(success);
        return returnData;
    }
}

// =============================================================================
// TRUE POSITIVES - Interface Calls
// =============================================================================

contract TP_InterfaceCalls {
    IERC20 public token;
    IVault public vault;

    constructor(address _token, address _vault) {
        token = IERC20(_token);
        vault = IVault(_vault);
    }

    // TP: ERC20 transfer via interface - should be detected
    function transferTokens(address to, uint256 amount) external returns (bool) {
        return token.transfer(to, amount);  // TP: External call through interface
    }

    // TP: ERC20 transferFrom via interface - should be detected
    function transferFromTokens(address from, address to, uint256 amount) external returns (bool) {
        return token.transferFrom(from, to, amount);  // TP: External call
    }

    // TP: ERC20 approve via interface - should be detected
    function approveTokens(address spender, uint256 amount) external returns (bool) {
        return token.approve(spender, amount);  // TP: External call
    }

    // TP: View function via interface - should be detected
    function getTokenBalance(address account) external view returns (uint256) {
        return token.balanceOf(account);  // TP: External view call
    }

    // TP: Vault deposit - should be detected
    function depositToVault(uint256 amount) external {
        vault.deposit(amount);  // TP: External call
    }

    // TP: Vault withdraw - should be detected
    function withdrawFromVault(uint256 amount) external {
        vault.withdraw(amount);  // TP: External call
    }
}

// =============================================================================
// TRUE POSITIVES - This Calls (External Self-Calls)
// =============================================================================

contract TP_ThisCalls {
    uint256 public value;

    function externalFunction() external returns (uint256) {
        value = 100;
        return value;
    }

    function anotherExternal(uint256 x) external pure returns (uint256) {
        return x * 2;
    }

    // TP: this.func() - external self-call should be detected
    function callThisSimple() public returns (uint256) {
        return this.externalFunction();  // TP: this.func()
    }

    // TP: this.func(args) - should be detected
    function callThisWithArgs(uint256 x) public pure returns (uint256) {
        return this.anotherExternal(x);  // TP: this.func(args)
    }

    // TP: Multiple this calls - all should be detected
    function callThisMultiple(uint256 x) public returns (uint256) {
        this.externalFunction();  // TP
        return this.anotherExternal(x);  // TP
    }
}

// =============================================================================
// TRUE POSITIVES - Ether Transfers
// =============================================================================

contract TP_EtherTransfers {
    // TP: transfer() - should be detected
    function sendWithTransfer(address payable to, uint256 amount) external {
        to.transfer(amount);  // TP: Ether transfer
    }

    // TP: send() - should be detected
    function sendWithSend(address payable to, uint256 amount) external returns (bool) {
        return to.send(amount);  // TP: Ether send
    }

    // TP: transfer with msg.value
    function forwardEther(address payable to) external payable {
        to.transfer(msg.value);  // TP: Forward ether
    }

    // TP: Conditional transfer
    function conditionalTransfer(address payable to, uint256 amount, bool shouldSend) external {
        if (shouldSend) {
            to.transfer(amount);  // TP: Conditional transfer
        }
    }
}

// =============================================================================
// TRUE POSITIVES - Contract Creation (External in sense of creating new contract)
// =============================================================================

contract TP_SimpleContract {
    uint256 public value;

    constructor(uint256 v) {
        value = v;
    }
}

contract TP_ContractCreation {
    // TP: new keyword creates external contract
    function createContract(uint256 v) external returns (address) {
        TP_SimpleContract c = new TP_SimpleContract(v);  // TP: Contract creation
        return address(c);
    }

    // TP: new with value
    function createWithValue() external payable returns (address) {
        TP_SimpleContract c = new TP_SimpleContract{value: msg.value}(100);  // TP
        return address(c);
    }
}

// =============================================================================
// FALSE POSITIVES - Internal Calls (Should NOT Be Detected as External)
// =============================================================================

contract FP_InternalCalls {
    uint256 public value;

    // FP: Internal function - NOT external
    function internalHelper(uint256 x) internal pure returns (uint256) {
        return x * 2;
    }

    // FP: Private function - NOT external
    function privateHelper(uint256 x) private pure returns (uint256) {
        return x + 1;
    }

    // FP: Public function called internally - NOT external when called within contract
    function publicHelper() public pure returns (uint256) {
        return 42;
    }

    // FP: Calling internal - should NOT be detected as external
    function callInternal() public pure returns (uint256) {
        return internalHelper(5);  // FP: Internal call
    }

    // FP: Calling private - should NOT be detected as external
    function callPrivate() public pure returns (uint256) {
        return privateHelper(10);  // FP: Private call
    }

    // FP: Calling public internally - should NOT be detected as external
    function callPublic() public pure returns (uint256) {
        return publicHelper();  // FP: Internal call to public function
    }

    // FP: Calling inherited function - should NOT be detected as external
    function callInherited() public pure returns (uint256) {
        return internalHelper(publicHelper());  // FP: All internal
    }
}

contract FP_Inherited is FP_InternalCalls {
    // FP: Calling parent's function - NOT external
    function callParentInternal() public pure returns (uint256) {
        return internalHelper(5);  // FP: Inherited internal call
    }
}

// =============================================================================
// FALSE POSITIVES - Built-in Functions
// =============================================================================

contract FP_BuiltinFunctions {
    // FP: require is NOT an external call
    function testRequire(uint256 x) external pure {
        require(x > 0, "Must be positive");  // FP: Built-in
    }

    // FP: assert is NOT an external call
    function testAssert(uint256 x) external pure {
        assert(x != 0);  // FP: Built-in
    }

    // FP: revert is NOT an external call
    function testRevert() external pure {
        revert("Error");  // FP: Built-in
    }

    // FP: keccak256 is NOT an external call
    function testHash(bytes calldata data) external pure returns (bytes32) {
        return keccak256(data);  // FP: Built-in
    }

    // FP: abi.encode is NOT an external call
    function testAbiEncode(uint256 x) external pure returns (bytes memory) {
        return abi.encode(x);  // FP: Built-in
    }

    // FP: abi.decode is NOT an external call
    function testAbiDecode(bytes calldata data) external pure returns (uint256) {
        return abi.decode(data, (uint256));  // FP: Built-in
    }

    // FP: ecrecover is NOT an external call
    function testEcrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(hash, v, r, s);  // FP: Built-in
    }

    // FP: addmod/mulmod are NOT external calls
    function testModArithmetic(uint256 a, uint256 b, uint256 n) external pure returns (uint256, uint256) {
        return (addmod(a, b, n), mulmod(a, b, n));  // FP: Built-in
    }

    // FP: blockhash is NOT an external call
    function testBlockhash(uint256 blockNumber) external view returns (bytes32) {
        return blockhash(blockNumber);  // FP: Built-in
    }
}

// =============================================================================
// EDGE CASES - Conditional External Calls
// =============================================================================

contract EC_ConditionalCalls {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // EC: External call in if branch
    function conditionalTransfer(address to, uint256 amount, bool shouldTransfer) external {
        if (shouldTransfer) {
            token.transfer(to, amount);  // EC: Conditional external call
        }
    }

    // EC: External call in else branch
    function conditionalTransferElse(address to, uint256 amount, bool useElse) external {
        if (!useElse) {
            // Do nothing
        } else {
            token.transfer(to, amount);  // EC: External call in else
        }
    }

    // EC: External call in ternary (less common)
    function ternaryCall(address a, address b, uint256 amount, bool useA) external returns (bool) {
        return useA ? token.transfer(a, amount) : token.transfer(b, amount);  // EC: Both are external
    }

    // EC: External call inside try-catch
    function tryCatchCall(address to, uint256 amount) external returns (bool) {
        try token.transfer(to, amount) returns (bool success) {  // EC: External in try
            return success;
        } catch {
            return false;
        }
    }
}

// =============================================================================
// EDGE CASES - Loops with External Calls
// =============================================================================

contract EC_LoopCalls {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // EC: External call in for loop
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            token.transfer(recipients[i], amount);  // EC: External call in loop
        }
    }

    // EC: External call in while loop
    function whileLoopCalls(address to, uint256 totalAmount) external {
        uint256 remaining = totalAmount;
        while (remaining > 0) {
            uint256 chunk = remaining > 100 ? 100 : remaining;
            token.transfer(to, chunk);  // EC: External call in while
            remaining -= chunk;
        }
    }

    // EC: Low-level call in loop (dangerous with msg.value)
    function loopedCalls(address[] calldata targets, bytes calldata data) external payable {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call{value: msg.value}(data);  // EC: Dangerous pattern
            require(success);
        }
    }
}

// =============================================================================
// EDGE CASES - Nested External Calls
// =============================================================================

contract EC_NestedCalls {
    IERC20 public token;
    IVault public vault;

    constructor(address _token, address _vault) {
        token = IERC20(_token);
        vault = IVault(_vault);
    }

    // EC: Multiple sequential external calls
    function sequentialCalls(address to, uint256 amount) external {
        token.approve(address(vault), amount);  // EC: First external
        vault.deposit(amount);  // EC: Second external
        token.transfer(to, amount);  // EC: Third external
    }

    // EC: External call with result used in another external call
    function chainedCalls(address user) external view returns (uint256) {
        uint256 balance = token.balanceOf(user);  // EC: First external
        if (balance > 0) {
            return vault.getBalance();  // EC: Second external (conditional)
        }
        return 0;
    }
}

// =============================================================================
// EDGE CASES - Callback Patterns
// =============================================================================

contract EC_CallbackPatterns {
    // EC: Contract that accepts callbacks
    function executeWithCallback(ICallback target, bytes calldata data) external {
        target.callback(data);  // EC: External call to callback
    }

    // EC: Reentrancy-prone pattern
    function vulnerableCallback(address target) external payable {
        (bool success, ) = target.call{value: msg.value}("");  // EC: External before state change
        require(success);
        // State change after external call - vulnerable
    }
}

// =============================================================================
// EDGE CASES - Assembly External Calls
// =============================================================================

contract EC_AssemblyCalls {
    // EC: External call via assembly (harder to detect)
    function assemblyCall(address target, bytes calldata data) external returns (bool) {
        bool success;
        assembly {
            // This is also an external call but via assembly
            success := call(gas(), target, 0, add(data.offset, 0x20), data.length, 0, 0)
        }
        return success;
    }

    // EC: Delegatecall via assembly
    function assemblyDelegatecall(address target, bytes calldata data) external returns (bool) {
        bool success;
        assembly {
            success := delegatecall(gas(), target, add(data.offset, 0x20), data.length, 0, 0)
        }
        return success;
    }
}

// =============================================================================
// EDGE CASES - Payable and Non-Payable
// =============================================================================

contract EC_PayablePatterns {
    // EC: Payable function making external call with value
    function payableExternal(address payable target) external payable {
        (bool success, ) = target.call{value: msg.value}("");  // EC: Payable external
        require(success);
    }

    // EC: Non-payable function making value transfer from balance
    function nonPayableTransfer(address payable to, uint256 amount) external {
        require(address(this).balance >= amount);
        to.transfer(amount);  // EC: Transfer from contract balance
    }

    // EC: receive() making external call
    receive() external payable {
        // Note: This is dangerous but valid
    }

    // EC: fallback() making external call
    fallback() external payable {
        // Note: This is dangerous but valid
    }
}

// =============================================================================
// EDGE CASES - State Variable Interface
// =============================================================================

contract EC_StateVariableInterface {
    IERC20 public immutable token;
    address public mutableTarget;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // EC: Call through immutable interface variable
    function callImmutable(address to, uint256 amount) external {
        token.transfer(to, amount);  // EC: Through immutable
    }

    // EC: Call through mutable address (could change)
    function callMutable(bytes calldata data) external {
        (bool success, ) = mutableTarget.call(data);  // EC: Through mutable address
        require(success);
    }

    function setTarget(address target) external {
        mutableTarget = target;
    }
}

// =============================================================================
// EDGE CASES - Parameter Interface
// =============================================================================

contract EC_ParameterInterface {
    // EC: External call through parameter - should be detected
    function callViaParam(IERC20 paramToken, address to, uint256 amount) external {
        paramToken.transfer(to, amount);  // EC: Through parameter interface
    }

    // EC: External call through address parameter
    function callViaAddress(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);  // EC: Through address parameter
        require(success);
    }

    // EC: External call through payable address parameter
    function transferViaParam(address payable to) external payable {
        to.transfer(msg.value);  // EC: Through payable address parameter
    }
}
