// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test cases for StorageCollision.ql detector
 * Tests for proxy pattern storage collision vulnerabilities
 */

// VULNERABLE: Proxy with state variables at standard slots
contract StorageCollisionProxy {
    // VULNERABLE: State at slot 0 - will collide with implementation
    address public implementation;
    // VULNERABLE: State at slot 1
    address public admin;

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

    receive() external payable {}
}

// VULNERABLE: Upgradeable contract with normal state variables
contract UpgradeableVulnerable {
    // VULNERABLE: These will collide between proxy and implementation
    address public owner;
    uint256 public value;
    mapping(address => uint256) public balances;

    function initialize(address _owner) external {
        owner = _owner;
    }
}

// SAFE: Using EIP-1967 storage slots
contract EIP1967Proxy {
    // SAFE: Uses random storage slot via keccak256
    bytes32 private constant IMPLEMENTATION_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 private constant ADMIN_SLOT =
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImpl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
    }

    fallback() external payable {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// SAFE: Using storage gap pattern
contract UpgradeableWithGap {
    address public owner;

    // SAFE: Storage gap for future upgrades
    uint256[50] private __gap;

    function initialize(address _owner) external {
        owner = _owner;
    }
}

// VULNERABLE: TransparentProxy pattern without proper storage
contract TransparentProxyVulnerable {
    // VULNERABLE: admin at slot 0
    address public proxyAdmin;
    // VULNERABLE: implementation at slot 1
    address public proxyImplementation;

    modifier ifAdmin() {
        if (msg.sender == proxyAdmin) {
            _;
        } else {
            _fallback();
        }
    }

    function upgradeTo(address newImpl) external ifAdmin {
        proxyImplementation = newImpl;
    }

    function _fallback() internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let impl := sload(1) // proxyImplementation slot
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _fallback();
    }
}

// SAFE: UUPS pattern with proper storage
contract UUPSProxy {
    // Uses EIP-1967 slot
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function _getImplementation() internal view returns (address) {
        address impl;
        assembly {
            impl := sload(_IMPLEMENTATION_SLOT)
        }
        return impl;
    }

    fallback() external payable {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// VULNERABLE: Diamond proxy with state at normal slots
contract DiamondProxyVulnerable {
    // VULNERABLE: facets mapping at slot 0
    mapping(bytes4 => address) public facets;
    // VULNERABLE: owner at slot 1
    address public owner;

    function setFacet(bytes4 selector, address facet) external {
        require(msg.sender == owner);
        facets[selector] = facet;
    }

    fallback() external payable {
        address facet = facets[msg.sig];
        require(facet != address(0));
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// SAFE: Constant/immutable variables don't use storage
contract ConstantsSafe {
    // SAFE: Constants don't use storage slots
    address public constant IMPLEMENTATION = 0x1234567890123456789012345678901234567890;
    uint256 public constant VERSION = 1;

    // SAFE: Immutables are stored in code, not storage
    address public immutable admin;

    constructor(address _admin) {
        admin = _admin;
    }
}
