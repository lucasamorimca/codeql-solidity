// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test cases for FlashLoanAttack.ql detector
 * Tests for flash loan vulnerability patterns
 */

// Mock interfaces
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

// VULNERABLE: Flash loan callback modifying state
contract FlashLoanCallbackVulnerable is IFlashLoanReceiver {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public votingPower;

    // VULNERABLE: Flash loan callback that modifies balance state
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        // VULNERABLE: Modifying balances during flash loan
        balances[initiator] += amounts[0];
        return true;
    }

    // VULNERABLE: onFlashLoan callback (ERC-3156 style)
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // VULNERABLE: State modification in flash loan callback
        balances[initiator] = amount;
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

// VULNERABLE: Governance without flash loan protection
contract GovernanceVulnerable {
    mapping(address => uint256) public votingPower;
    mapping(uint256 => uint256) public proposalVotes;

    // VULNERABLE: Vote function without flash loan protection
    function vote(uint256 proposalId) external {
        uint256 power = votingPower[msg.sender];
        proposalVotes[proposalId] += power;
    }

    // VULNERABLE: castVote without protection
    function castVote(uint256 proposalId, bool support) external {
        uint256 power = votingPower[msg.sender];
        if (support) {
            proposalVotes[proposalId] += power;
        }
    }

    // VULNERABLE: delegate without timelock
    function delegate(address delegatee) external {
        votingPower[delegatee] += votingPower[msg.sender];
        votingPower[msg.sender] = 0;
    }
}

// VULNERABLE: Price-based operations without flash loan checks
contract PriceBasedVulnerable {
    mapping(address => uint256) public reserves;

    // VULNERABLE: Uses reserve-based pricing
    function getPrice() public view returns (uint256) {
        return reserves[address(this)];
    }

    // VULNERABLE: Swap using manipulable price
    function swap(uint256 amountIn) external {
        uint256 price = getPrice();
        uint256 amountOut = amountIn * price / 1e18;
        // Execute swap...
    }

    // VULNERABLE: Uses totalSupply which can be manipulated
    function calculateShare(uint256 amount) external view returns (uint256) {
        uint256 supply = IERC20(address(this)).totalSupply();
        return amount * 1e18 / supply;
    }

    // VULNERABLE: Uses balance for calculation
    function getPoolValue() external view returns (uint256) {
        return IERC20(address(this)).balanceOf(address(this));
    }
}

// SAFE: Has nonReentrant modifier
contract FlashLoanProtectedReentrancy {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }

    // SAFE: Protected by nonReentrant
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external nonReentrant returns (bool) {
        balances[initiator] += amounts[0];
        return true;
    }
}

// SAFE: Has timelock protection
contract TimelockProtected {
    mapping(address => uint256) public lastAction;
    uint256 public constant TIMELOCK_DELAY = 1 days;

    modifier withTimelock() {
        require(block.number > lastAction[msg.sender] + TIMELOCK_DELAY, "Timelock active");
        lastAction[msg.sender] = block.number;
        _;
    }

    // SAFE: Protected by timelock
    function vote(uint256 proposalId) external withTimelock {
        // Vote logic
    }
}

// SAFE: Uses snapshot/commit-reveal
contract SnapshotProtected {
    mapping(address => uint256) public committedVotes;
    mapping(address => bytes32) public commitments;

    // SAFE: Commit phase (can't be exploited in same tx)
    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
    }

    // SAFE: Reveal phase (requires previous commit)
    function reveal(uint256 proposalId, uint256 vote, bytes32 salt) external {
        require(commitments[msg.sender] == keccak256(abi.encodePacked(proposalId, vote, salt)), "Invalid reveal");
        committedVotes[msg.sender] = vote;
    }
}

// VULNERABLE: Public external function manipulating balances
contract PublicBalanceManipulation {
    mapping(address => uint256) public stakes;
    uint256 public totalStake;

    // VULNERABLE: External function affecting stakes
    function stake(uint256 amount) external {
        stakes[msg.sender] += amount;
        totalStake += amount;
    }

    // VULNERABLE: External function using stake for calculation
    function getReward() external view returns (uint256) {
        return stakes[msg.sender] * 100 / totalStake;
    }
}

// SAFE: Private/internal functions
contract InternalFunctions {
    mapping(address => uint256) public balances;

    // SAFE: Internal function
    function _updateBalance(address user, uint256 amount) internal {
        balances[user] = amount;
    }

    // SAFE: Private function
    function _calculateReward(uint256 stake) private pure returns (uint256) {
        return stake * 10 / 100;
    }
}

// VULNERABLE: Quorum-based governance
contract QuorumVulnerable {
    uint256 public quorum;
    mapping(uint256 => uint256) public proposalSupport;

    // VULNERABLE: Quorum can be met with flash-loaned tokens
    function checkQuorum(uint256 proposalId) external view returns (bool) {
        return proposalSupport[proposalId] >= quorum;
    }

    // VULNERABLE: Vote affects quorum calculation
    function voteForProposal(uint256 proposalId, uint256 amount) external {
        proposalSupport[proposalId] += amount;
    }
}
