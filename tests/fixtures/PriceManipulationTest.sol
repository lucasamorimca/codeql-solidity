// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Test cases for PriceManipulation.ql detector
 * Tests for spot price manipulation vulnerabilities
 */

// Mock interfaces
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
    function token1() external view returns (address);
}

interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96,
        int24 tick,
        uint16 observationIndex,
        uint16 observationCardinality,
        uint16 observationCardinalityNext,
        uint8 feeProtocol,
        bool unlocked
    );
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

interface IChainlinkOracle {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

// VULNERABLE: Using spot price from Uniswap V2
contract SpotPriceVulnerable {
    IUniswapV2Pair public pair;

    // VULNERABLE: Direct use of getReserves() for pricing
    function getSpotPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return uint256(reserve0) * 1e18 / uint256(reserve1);
    }

    // VULNERABLE: Swap using spot price
    function swap(uint256 amountIn) external returns (uint256) {
        uint256 price = getSpotPrice();
        uint256 amountOut = amountIn * price / 1e18;
        // ... execute swap
        return amountOut;
    }

    // VULNERABLE: Collateral valuation using spot price
    function getCollateralValue(uint256 amount) public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        uint256 price = uint256(reserve0) * 1e18 / uint256(reserve1);
        return amount * price / 1e18;
    }
}

// VULNERABLE: Using Uniswap V3 slot0 for pricing
contract UniswapV3SpotVulnerable {
    IUniswapV3Pool public pool;

    // VULNERABLE: slot0() gives current tick, easily manipulated
    function getCurrentPrice() public view returns (uint256) {
        (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
        // Convert sqrtPriceX96 to price
        return uint256(sqrtPriceX96) * uint256(sqrtPriceX96) / (1 << 192);
    }

    // VULNERABLE: Using slot0 for important calculation
    function calculateValue(uint256 amount) external view returns (uint256) {
        uint256 price = getCurrentPrice();
        return amount * price;
    }
}

// VULNERABLE: Using balanceOf for pricing
contract BalanceBasedPrice {
    IERC20 public token0;
    IERC20 public token1;
    address public poolAddress;

    // VULNERABLE: balanceOf can be manipulated with flash loans
    function getPrice() public view returns (uint256) {
        uint256 balance0 = token0.balanceOf(poolAddress);
        uint256 balance1 = token1.balanceOf(poolAddress);
        return balance0 * 1e18 / balance1;
    }
}

// SAFE: Using TWAP from Uniswap V3
contract TWAPSafe {
    IUniswapV3Pool public pool;

    // SAFE: Uses observe() for TWAP
    function getTWAP(uint32 period) public view returns (int56) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = period;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
        return (tickCumulatives[1] - tickCumulatives[0]) / int56(int32(period));
    }

    // SAFE: Price calculation using TWAP
    function getPriceWithTWAP() external view returns (int56) {
        return getTWAP(1800); // 30 minute TWAP
    }
}

// SAFE: Using Chainlink oracle
contract ChainlinkSafe {
    IChainlinkOracle public oracle;

    // SAFE: Chainlink oracle is manipulation-resistant
    function getPrice() public view returns (int256) {
        return oracle.latestAnswer();
    }

    // SAFE: Using latestRoundData with staleness check
    function getPriceWithCheck() public view returns (int256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = oracle.latestRoundData();

        require(updatedAt > block.timestamp - 3600, "Stale price");
        require(answeredInRound >= roundId, "Stale round");

        return answer;
    }
}

// VULNERABLE: Mixed - some safe, some not
contract MixedPriceOracle {
    IUniswapV2Pair public pair;
    IChainlinkOracle public chainlink;

    // VULNERABLE: Spot price without protection
    function getSpotPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r0) / uint256(r1);
    }

    // SAFE: Chainlink price
    function getOraclePrice() public view returns (int256) {
        return chainlink.latestAnswer();
    }

    // VULNERABLE: Uses spot price in critical calculation
    function calculateLiquidation(uint256 collateral, uint256 debt) external view returns (bool) {
        uint256 price = getSpotPrice();  // VULNERABLE
        uint256 collateralValue = collateral * price;
        return collateralValue < debt * 15 / 10;  // 150% collateralization
    }
}

// VULNERABLE: AMM-style getAmountOut
contract AMMPriceVulnerable {
    // VULNERABLE: getAmountOut based on current reserves
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }

    // VULNERABLE: Using getRate style function
    function getRate(uint256 amount) external pure returns (uint256) {
        // Simplified rate calculation - vulnerable to manipulation
        return amount * 99 / 100;
    }
}

// SAFE: Using consult pattern (like Uniswap V2 Oracle)
contract ConsultPatternSafe {
    // SAFE: consult() typically implies TWAP
    function consult(address token, uint256 amountIn) external pure returns (uint256) {
        // Would use cumulative prices for TWAP
        return amountIn;  // Placeholder
    }

    function getPriceWithConsult(address token, uint256 amount) external view returns (uint256) {
        return this.consult(token, amount);
    }
}
