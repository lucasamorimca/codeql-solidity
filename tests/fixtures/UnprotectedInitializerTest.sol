// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test cases for UnprotectedInitializer.ql detector
 * Tests for upgradeable contract initializer vulnerabilities
 */

// VULNERABLE: Public initializer without protection
contract UnprotectedInitializerVulnerable {
    address public owner;
    uint256 public value;
    bool private _initialized;

    // VULNERABLE: No protection, anyone can call
    function initialize(address _owner) public {
        owner = _owner;
    }

    // VULNERABLE: External initializer without protection
    function initializeValue(uint256 _value) external {
        value = _value;
    }

    // VULNERABLE: setup function (common alias for initialize)
    function setup(address _owner, uint256 _value) public {
        owner = _owner;
        value = _value;
    }

    // VULNERABLE: init function
    function init(address _owner) external {
        owner = _owner;
    }
}

// SAFE: Protected initializers
contract ProtectedInitializerSafe {
    address public owner;
    uint256 public value;
    bool private initialized;

    // SAFE: Has require(!initialized) check
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = _owner;
    }

    // SAFE: Has initializing check
    bool private initializing;
    function initializeWithFlag(address _owner) public {
        require(!initializing, "Already initializing");
        initializing = true;
        owner = _owner;
        initializing = false;
    }
}

// SAFE: Using OpenZeppelin-style initializer modifier
contract OZStyleInitializer {
    address public owner;
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _;
    }

    // SAFE: Has initializer modifier
    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}

// SAFE: Using onlyInitializing modifier
contract OnlyInitializingStyle {
    address public owner;
    bool private _initializing;

    modifier onlyInitializing() {
        require(_initializing, "Not initializing");
        _;
    }

    // SAFE: Has onlyInitializing modifier
    function __init(address _owner) internal onlyInitializing {
        owner = _owner;
    }
}

// VULNERABLE: Initializer that sets critical roles
contract CriticalRoleInitializer {
    address public admin;
    address public governance;
    address public controller;
    address public manager;
    address public operator;

    // VULNERABLE: Sets admin without protection
    function initializeAdmin(address _admin) public {
        admin = _admin;
    }

    // VULNERABLE: Sets governance without protection
    function initializeGovernance(address _governance) external {
        governance = _governance;
    }

    // VULNERABLE: Sets controller without protection
    function setupController(address _controller) public {
        controller = _controller;
    }

    // VULNERABLE: Sets manager without protection
    function initManager(address _manager) external {
        manager = _manager;
    }

    // VULNERABLE: Sets operator without protection
    function initializeOperator(address _operator) public {
        operator = _operator;
    }
}

// SAFE: Internal initializer
contract InternalInitializer {
    address public owner;

    // SAFE: Internal function, not directly callable
    function _initialize(address _owner) internal {
        owner = _owner;
    }

    // SAFE: Private function
    function __initialize(address _owner) private {
        owner = _owner;
    }
}

// VULNERABLE: Upgradeable proxy pattern without protection
contract UpgradeableVulnerable {
    address public implementation;
    address public owner;

    // VULNERABLE: Can be re-initialized after upgrade
    function initialize(address _owner) public {
        owner = _owner;
    }

    function upgradeTo(address newImpl) external {
        require(msg.sender == owner);
        implementation = newImpl;
    }
}
