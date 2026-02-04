// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test file for Taint Tracking
 *
 * TRUE POSITIVES (TP_): Tainted data flows that SHOULD be detected
 * FALSE POSITIVES (FP_): Flows that should NOT be flagged
 * EDGE CASES (EC_): Boundary conditions for taint tracking
 */

// =============================================================================
// TRUE POSITIVES - User Input Taint Sources
// =============================================================================

contract TP_UserInputSources {
    uint256 public value;
    address public lastSender;

    // TP: msg.sender is a taint source
    function useMsgSender() public {
        lastSender = msg.sender;  // TP: Tainted from msg.sender
    }

    // TP: msg.value is a taint source
    function useMsgValue() public payable {
        value = msg.value;  // TP: Tainted from msg.value
    }

    // TP: msg.data is a taint source
    function useMsgData() public returns (bytes memory) {
        return msg.data;  // TP: Tainted from msg.data
    }

    // TP: tx.origin is a taint source
    function useTxOrigin() public {
        lastSender = tx.origin;  // TP: Tainted from tx.origin
    }

    // TP: tx.gasprice is a taint source
    function useTxGasprice() public view returns (uint256) {
        return tx.gasprice;  // TP: Tainted from tx.gasprice
    }

    // TP: block.timestamp is a taint source
    function useBlockTimestamp() public view returns (uint256) {
        return block.timestamp;  // TP: Tainted from block.timestamp
    }

    // TP: block.number is a taint source
    function useBlockNumber() public view returns (uint256) {
        return block.number;  // TP: Tainted from block.number
    }

    // TP: block.coinbase is a taint source
    function useBlockCoinbase() public view returns (address) {
        return block.coinbase;  // TP: Tainted from block.coinbase
    }
}

// =============================================================================
// TRUE POSITIVES - Function Parameter Taint Sources
// =============================================================================

contract TP_ParameterTaint {
    uint256 public storedValue;
    address public storedAddress;
    bytes public storedData;

    // TP: External function parameters are tainted
    function externalWithParams(uint256 value, address addr) external {
        storedValue = value;    // TP: Tainted from parameter
        storedAddress = addr;   // TP: Tainted from parameter
    }

    // TP: Public function parameters are tainted
    function publicWithParams(uint256 value) public {
        storedValue = value;    // TP: Tainted from parameter
    }

    // TP: Bytes parameter (calldata injection)
    function withBytesParam(bytes calldata data) external {
        storedData = data;      // TP: Tainted from parameter
    }

    // TP: Array parameter
    function withArrayParam(uint256[] calldata values) external {
        if (values.length > 0) {
            storedValue = values[0];  // TP: Tainted from array parameter
        }
    }
}

// =============================================================================
// TRUE POSITIVES - Taint Propagation Through Operations
// =============================================================================

contract TP_TaintPropagation {
    uint256 public result;

    // TP: Arithmetic propagates taint
    function arithmeticPropagation(uint256 taintedInput) external {
        uint256 a = taintedInput + 10;    // TP: Tainted
        uint256 b = a * 2;                 // TP: Tainted (from a)
        uint256 c = b - 5;                 // TP: Tainted (from b)
        uint256 d = c / 2;                 // TP: Tainted (from c)
        result = d % 100;                  // TP: Tainted (from d)
    }

    // TP: Bitwise operations propagate taint
    function bitwisePropagation(uint256 taintedInput) external {
        uint256 a = taintedInput & 0xFF;   // TP: Tainted
        uint256 b = a | 0x100;             // TP: Tainted
        uint256 c = b ^ 0x55;              // TP: Tainted
        uint256 d = c << 2;                // TP: Tainted
        result = d >> 1;                   // TP: Tainted
    }

    // TP: String concatenation propagates taint (via abi.encodePacked)
    function stringPropagation(string calldata taintedStr) external pure returns (bytes memory) {
        return abi.encodePacked("prefix_", taintedStr, "_suffix");  // TP: Tainted
    }

    // TP: Array operations propagate taint
    function arrayPropagation(uint256 taintedIndex) external view returns (uint256) {
        uint256[] memory arr = new uint256[](10);
        return arr[taintedIndex];  // TP: Tainted index - potential out of bounds
    }
}

// =============================================================================
// TRUE POSITIVES - External Call Results as Taint
// =============================================================================

interface IExternalContract {
    function getValue() external view returns (uint256);
    function getAddress() external view returns (address);
    function getData() external view returns (bytes memory);
}

contract TP_ExternalCallTaint {
    IExternalContract public externalContract;
    uint256 public storedValue;

    constructor(address _external) {
        externalContract = IExternalContract(_external);
    }

    // TP: External call result is tainted
    function useExternalValue() external {
        uint256 value = externalContract.getValue();  // TP: Tainted from external
        storedValue = value;                           // TP: Tainted propagation
    }

    // TP: External address result is tainted
    function useExternalAddress() external {
        address addr = externalContract.getAddress();  // TP: Tainted from external
        payable(addr).transfer(1 ether);               // TP: Tainted sink (transfer to tainted address)
    }

    // TP: Low-level call result is tainted
    function lowLevelCallResult(address target) external returns (bytes memory) {
        (bool success, bytes memory data) = target.call("");  // TP: data is tainted
        require(success);
        return data;  // TP: Returning tainted data
    }
}

// =============================================================================
// TRUE POSITIVES - Taint to Sensitive Sinks
// =============================================================================

contract TP_TaintToSinks {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // TP: Tainted input to external call
    function taintedExternalCall(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);  // TP: Both target and data are tainted
        require(success);
    }

    // TP: Tainted input to delegatecall (critical!)
    function taintedDelegatecall(address target) external {
        (bool success, ) = target.delegatecall("");  // TP: Critical - tainted delegatecall target
        require(success);
    }

    // TP: Tainted input to transfer
    function taintedTransfer(address payable recipient, uint256 amount) external {
        recipient.transfer(amount);  // TP: Tainted recipient and amount
    }

    // TP: Tainted input to selfdestruct (critical!)
    function taintedSelfdestruct(address payable recipient) external {
        selfdestruct(recipient);  // TP: Critical - tainted selfdestruct recipient
    }

    // TP: Tainted input to create (contract creation)
    function taintedCreate(bytes calldata bytecode) external returns (address) {
        address newContract;
        assembly {
            newContract := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        return newContract;  // TP: Created from tainted bytecode
    }
}

// =============================================================================
// TRUE POSITIVES - Cross-Function Taint Flow
// =============================================================================

contract TP_CrossFunctionTaint {
    uint256 private taintedValue;

    // TP: Store tainted value
    function storeTainted(uint256 value) external {
        taintedValue = value;  // Tainted parameter stored
    }

    // TP: Use stored tainted value
    function useTainted() external view returns (uint256) {
        return taintedValue * 2;  // TP: Using tainted storage value
    }

    // TP: Internal function call preserves taint
    function internalHelper(uint256 value) internal pure returns (uint256) {
        return value + 100;  // TP: Propagates taint
    }

    function useInternalHelper(uint256 taintedInput) external pure returns (uint256) {
        return internalHelper(taintedInput);  // TP: Taint flows through internal call
    }

    // TP: Multiple hops
    function hop1(uint256 x) internal pure returns (uint256) { return x + 1; }
    function hop2(uint256 x) internal pure returns (uint256) { return hop1(x) * 2; }
    function hop3(uint256 x) internal pure returns (uint256) { return hop2(x) - 1; }

    function multiHopTaint(uint256 tainted) external pure returns (uint256) {
        return hop3(tainted);  // TP: Taint flows through 3 hops
    }
}

// =============================================================================
// FALSE POSITIVES - Sanitized/Safe Data
// =============================================================================

contract FP_SanitizedData {
    address public owner;
    uint256 public constant SAFE_VALUE = 100;

    constructor() {
        owner = msg.sender;
    }

    // FP: Constant value - not tainted
    function useConstant() external pure returns (uint256) {
        return SAFE_VALUE;  // FP: Constant, not tainted
    }

    // FP: Literal value - not tainted
    function useLiteral() external pure returns (uint256) {
        return 42;  // FP: Literal, not tainted
    }

    // FP: Validated/sanitized input
    function validateAndUse(address addr) external pure returns (address) {
        require(addr != address(0), "Invalid address");  // Sanitization
        require(uint160(addr) > 1000, "Address too low"); // Additional check
        return addr;  // FP: Considered sanitized after validation
    }

    // FP: Bounded value
    function boundedValue(uint256 value) external pure returns (uint256) {
        if (value > 100) {
            value = 100;  // Bounded
        }
        return value;  // FP: Value is bounded/sanitized
    }

    // FP: Whitelist check
    mapping(address => bool) public whitelist;

    function whitelistedOnly(address addr) external view returns (address) {
        require(whitelist[addr], "Not whitelisted");
        return addr;  // FP: Whitelisted addresses considered safe
    }
}

contract FP_InternalOnly {
    uint256 private internalValue;

    // FP: Internal function - parameters from trusted callers
    function internalFunc(uint256 value) internal {
        internalValue = value;  // FP: Internal, from trusted source
    }

    // FP: Private function - parameters from trusted callers
    function privateFunc(uint256 value) private pure returns (uint256) {
        return value * 2;  // FP: Private, from trusted source
    }

    // Entry point that sanitizes before internal call
    function publicEntry(uint256 value) external {
        require(value <= 1000, "Too large");  // Sanitization
        internalFunc(value);  // Safe internal call
    }
}

// =============================================================================
// EDGE CASES - Complex Taint Scenarios
// =============================================================================

// EC: Conditional taint
contract EC_ConditionalTaint {
    uint256 public result;

    // EC: Taint depends on condition
    function conditionalTaint(uint256 tainted, bool useIt) external {
        if (useIt) {
            result = tainted;  // EC: Tainted path
        } else {
            result = 100;      // EC: Safe path
        }
    }

    // EC: Ternary taint
    function ternaryTaint(uint256 tainted, bool flag) external pure returns (uint256) {
        return flag ? tainted : 42;  // EC: Conditionally tainted
    }
}

// EC: Loop taint propagation
contract EC_LoopTaint {
    // EC: Taint in loop
    function loopTaint(uint256[] calldata taintedArray) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < taintedArray.length; i++) {
            sum += taintedArray[i];  // EC: Accumulates taint
        }
        return sum;  // EC: Tainted result
    }

    // EC: Loop index from tainted source
    function taintedLoopBound(uint256 bound) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < bound; i++) {  // EC: Tainted loop bound
            sum += i;
        }
        return sum;
    }
}

// EC: Storage taint
contract EC_StorageTaint {
    mapping(address => uint256) public balances;
    mapping(uint256 => address) public owners;

    // EC: Taint flows into storage
    function depositTainted() external payable {
        balances[msg.sender] += msg.value;  // EC: msg.sender and msg.value both tainted
    }

    // EC: Taint from storage lookup
    function getBalance(address user) external view returns (uint256) {
        return balances[user];  // EC: user is tainted, result depends on tainted key
    }

    // EC: Double taint (key and value)
    function setOwner(uint256 tokenId, address owner) external {
        owners[tokenId] = owner;  // EC: Both key and value tainted
    }
}

// EC: Array/struct taint
contract EC_ComplexTypeTaint {
    struct UserData {
        address user;
        uint256 balance;
        bytes data;
    }

    UserData public userData;

    // EC: Struct field taint
    function setUserData(address user, uint256 balance, bytes calldata data) external {
        userData = UserData(user, balance, data);  // EC: All fields tainted
    }

    // EC: Array element taint
    function processArray(uint256[] calldata values) external pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            result[i] = values[i] * 2;  // EC: Each element tainted
        }
        return result;
    }
}

// EC: Taint through modifiers
contract EC_ModifierTaint {
    uint256 public value;

    // EC: Modifier that uses tainted parameter
    modifier withValue(uint256 val) {
        require(val > 0, "Value must be positive");
        _;
    }

    // EC: Tainted parameter flows through modifier
    function modifiedFunc(uint256 tainted) external withValue(tainted) {
        value = tainted;  // EC: Taint passes through modifier
    }
}

// EC: Inheritance taint
contract EC_BaseTaint {
    uint256 public baseValue;

    function setBase(uint256 value) public virtual {
        baseValue = value;  // Tainted
    }
}

contract EC_DerivedTaint is EC_BaseTaint {
    uint256 public derivedValue;

    // EC: Override maintains taint
    function setBase(uint256 value) public override {
        baseValue = value * 2;     // EC: Still tainted
        derivedValue = value + 1;  // EC: Still tainted
    }

    // EC: Call to base with taint
    function setBoth(uint256 value) external {
        super.setBase(value);  // EC: Taint flows to base
        derivedValue = value;  // EC: Also tainted here
    }
}

// EC: Library call taint
library EC_TaintLibrary {
    function process(uint256 value) internal pure returns (uint256) {
        return value * 2;
    }
}

contract EC_LibraryTaint {
    using EC_TaintLibrary for uint256;

    // EC: Taint through library using statement
    function useLibrary(uint256 tainted) external pure returns (uint256) {
        return tainted.process();  // EC: Taint flows through library
    }

    // EC: Direct library call
    function directLibrary(uint256 tainted) external pure returns (uint256) {
        return EC_TaintLibrary.process(tainted);  // EC: Taint flows through library
    }
}

// EC: ABI encoding/decoding taint
contract EC_AbiTaint {
    // EC: Taint through abi.encode
    function encodeData(uint256 tainted) external pure returns (bytes memory) {
        return abi.encode(tainted);  // EC: Result is tainted
    }

    // EC: Taint through abi.decode
    function decodeData(bytes calldata data) external pure returns (uint256) {
        return abi.decode(data, (uint256));  // EC: data is tainted, result is tainted
    }

    // EC: Taint through abi.encodeWithSelector
    function encodeWithSelector(uint256 tainted) external pure returns (bytes memory) {
        return abi.encodeWithSelector(bytes4(0x12345678), tainted);  // EC: Tainted
    }
}

// EC: Hash function taint
contract EC_HashTaint {
    // EC: Taint through keccak256
    function hashData(bytes calldata tainted) external pure returns (bytes32) {
        return keccak256(tainted);  // EC: Result depends on tainted input
    }

    // EC: Taint through sha256
    function sha256Data(bytes calldata tainted) external pure returns (bytes32) {
        return sha256(tainted);  // EC: Result depends on tainted input
    }

    // EC: Signature verification with tainted data
    function verifySignature(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external pure returns (address) {
        return ecrecover(hash, v, r, s);  // EC: All params tainted
    }
}

// EC: Event emission with tainted data
contract EC_EventTaint {
    event TaintedEvent(address indexed user, uint256 value, bytes data);

    // EC: Emitting tainted data in event (not a sink but worth tracking)
    function emitTainted(uint256 value, bytes calldata data) external {
        emit TaintedEvent(msg.sender, value, data);  // EC: All values tainted
    }
}

// EC: Revert with tainted message
contract EC_RevertTaint {
    // EC: Tainted data in revert message
    function revertWithTainted(string calldata reason) external pure {
        revert(reason);  // EC: Tainted revert reason
    }

    // EC: Tainted data in require message
    function requireWithTainted(bool condition, string calldata reason) external pure {
        require(condition, reason);  // EC: Tainted require reason
    }
}

// EC: Memory/calldata transitions
contract EC_MemoryTaint {
    // EC: Calldata to memory copy preserves taint
    function calldataToMemory(bytes calldata data) external pure returns (bytes memory) {
        bytes memory memData = data;  // EC: Taint preserved in copy
        return memData;
    }

    // EC: Multiple memory operations
    function multipleMemOps(uint256[] calldata input) external pure returns (uint256) {
        uint256[] memory temp1 = input;           // EC: Tainted
        uint256[] memory temp2 = new uint256[](temp1.length);
        for (uint256 i = 0; i < temp1.length; i++) {
            temp2[i] = temp1[i];                  // EC: Taint preserved
        }
        return temp2.length > 0 ? temp2[0] : 0;   // EC: Tainted result
    }
}

// EC: Assembly taint
contract EC_AssemblyTaint {
    // EC: Taint through assembly
    function assemblyTaint(uint256 tainted) external pure returns (uint256) {
        uint256 result;
        assembly {
            result := add(tainted, 1)  // EC: Taint in assembly
        }
        return result;  // EC: Tainted result
    }

    // EC: calldataload is tainted
    function calldataloadTaint() external pure returns (bytes32) {
        bytes32 result;
        assembly {
            result := calldataload(0)  // EC: Raw calldata is tainted
        }
        return result;
    }

    // EC: sload from tainted slot
    function sloadTaint(uint256 slot) external view returns (uint256) {
        uint256 result;
        assembly {
            result := sload(slot)  // EC: Tainted slot access
        }
        return result;
    }
}
