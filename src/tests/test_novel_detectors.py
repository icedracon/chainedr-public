"""
Pytest fixtures for all novel static-analyzer detectors.

Each detector has:
  - POSITIVE case: minimal Solidity snippet that MUST fire the detector (expect >= 1 real finding)
  - NEGATIVE case: clean variant that MUST NOT fire (expect 0 real findings)

Run:  pytest tests/test_novel_detectors.py -v
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from static_analyzer import SolidityStaticAnalyzer, StaticSeverity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sa():
    return SolidityStaticAnalyzer()


def _real(res):
    """Return non-FP findings."""
    return [f for f in res.findings if not f.is_false_positive]


def _titled(findings, keyword):
    return [f for f in findings if keyword.lower() in f.title.lower()]


def _analyze(sa, src):
    return sa.analyze(src, use_slither=False, use_ast=False)


# ---------------------------------------------------------------------------
# 1. Accrual-gate DoS
# ---------------------------------------------------------------------------

_ACCRUAL_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public rate;
    uint256 public started;
    function accrue() public {
        uint256 amt = totalSupply() * rate;
        require(amt > 0, "NoMintableAmount");
    }
    function updateRate(uint256 newRate) external onlyOwner {
        if (started != 0) accrue();
        rate = newRate;
    }
    modifier onlyOwner() { _; }
    function totalSupply() internal view returns (uint256) { return 1e18; }
}
"""

_ACCRUAL_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public rate;
    function accrue() public {
        uint256 amt = totalSupply() * rate;
        require(amt > 0, "NoMintableAmount");
    }
    function updateRate(uint256 newRate) external onlyOwner {
        require(newRate > 0, "Rate cannot be zero");
        accrue();
        rate = newRate;
    }
    modifier onlyOwner() { _; }
    function totalSupply() internal view returns (uint256) { return 1e18; }
}
"""

def test_accrual_gate_dos_fires(sa):
    res = _analyze(sa, _ACCRUAL_POSITIVE)
    hits = _titled(_real(res), "Accrual-gate")
    assert len(hits) >= 1, f"Expected accrual-gate finding, got: {[f.title for f in _real(res)]}"
    assert hits[0].severity in (StaticSeverity.HIGH, StaticSeverity.CRITICAL)

def test_accrual_gate_dos_clean(sa):
    res = _analyze(sa, _ACCRUAL_NEGATIVE)
    hits = _titled(_real(res), "Accrual-gate")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 2. Donation inflation attack
# ---------------------------------------------------------------------------

_DONATION_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalDeposited;
    mapping(address => uint256) public shares;
    function deposit(uint256 amount) external {
        uint256 newShares = amount * totalShares() / totalDeposited;
        shares[msg.sender] += newShares;
        totalDeposited += amount;
    }
    function totalShares() public view returns (uint256) { return 1e18; }
}
"""

_DONATION_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalDeposited;
    mapping(address => uint256) public shares;
    uint256 constant DEAD_SHARES = 1000;
    function deposit(uint256 amount) external {
        uint256 supply = totalShares();
        uint256 newShares;
        if (supply == 0) {
            newShares = amount - DEAD_SHARES;
        } else {
            newShares = amount * supply / totalDeposited;
        }
        shares[msg.sender] += newShares;
        totalDeposited += amount;
    }
    function totalShares() public view returns (uint256) { return 1e18; }
}
"""

def test_donation_inflation_fires(sa):
    res = _analyze(sa, _DONATION_POSITIVE)
    hits = _titled(_real(res), "Donation inflation")
    assert len(hits) >= 1, f"Expected donation inflation finding, got: {[f.title for f in _real(res)]}"

def test_donation_inflation_clean(sa):
    res = _analyze(sa, _DONATION_NEGATIVE)
    hits = _titled(_real(res), "Donation inflation")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 3. Governance sandwich
# ---------------------------------------------------------------------------

_SANDWICH_POSITIVE = """
pragma solidity ^0.8.0;
contract DEX {
    uint256 public fee;
    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
    function swap(uint256 amountIn) external returns (uint256) {
        uint256 amountOut = amountIn - (amountIn * fee / 1e18);
        _transfer(address(this), msg.sender, amountOut);
        return amountOut;
    }
    function _transfer(address from, address to, uint256 amount) internal {}
    modifier onlyOwner() { _; }
}
"""

_SANDWICH_NEGATIVE = """
pragma solidity ^0.8.0;
contract DEX {
    uint256 constant FEE = 30;
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        amountOut = amountIn - (amountIn * FEE / 10000);
        _transfer(address(this), msg.sender, amountOut);
    }
    function _transfer(address from, address to, uint256 amount) internal {}
}
"""

def test_governance_sandwich_fires(sa):
    res = _analyze(sa, _SANDWICH_POSITIVE)
    hits = _titled(_real(res), "Governance sandwich")
    assert len(hits) >= 1, f"Expected sandwich finding, got: {[f.title for f in _real(res)]}"

def test_governance_sandwich_clean(sa):
    res = _analyze(sa, _SANDWICH_NEGATIVE)
    hits = _titled(_real(res), "Governance sandwich")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 4. Read-only reentrancy
# ---------------------------------------------------------------------------

_READONLY_REENTRANT_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalAssets;
    modifier nonReentrant() { _; }
    function withdraw(uint256 amount) external nonReentrant {
        (bool ok,) = msg.sender.call{value: amount}("");
        totalAssets -= amount;
    }
    function getPrice() external view returns (uint256) {
        return totalAssets;
    }
}
"""

_READONLY_REENTRANT_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalAssets;
    modifier nonReentrant() { _; }
    function withdraw(uint256 amount) external nonReentrant {
        totalAssets -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
    }
    function getPrice() external view returns (uint256) {
        return totalAssets;
    }
}
"""

def test_read_only_reentrancy_fires(sa):
    res = _analyze(sa, _READONLY_REENTRANT_POSITIVE)
    hits = _titled(_real(res), "Read-only reentrancy")
    assert len(hits) >= 1, f"Expected read-only reentrancy, got: {[f.title for f in _real(res)]}"
    assert hits[0].severity == StaticSeverity.HIGH

def test_read_only_reentrancy_clean(sa):
    res = _analyze(sa, _READONLY_REENTRANT_NEGATIVE)
    hits = _titled(_real(res), "Read-only reentrancy")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 5. Incomplete pausable
# ---------------------------------------------------------------------------

_PAUSABLE_POSITIVE = """
pragma solidity ^0.8.0;
import "@openzeppelin/security/Pausable.sol";
contract Pool is Pausable {
    mapping(address => uint256) public deposits;
    function deposit(uint256 amt) external whenNotPaused {
        deposits[msg.sender] += amt;
    }
    function withdraw(uint256 amt) external {
        deposits[msg.sender] -= amt;
    }
}
"""

_PAUSABLE_NEGATIVE = """
pragma solidity ^0.8.0;
import "@openzeppelin/security/Pausable.sol";
contract Pool is Pausable {
    mapping(address => uint256) public deposits;
    function deposit(uint256 amt) external whenNotPaused {
        deposits[msg.sender] += amt;
    }
    function withdraw(uint256 amt) external whenNotPaused {
        deposits[msg.sender] -= amt;
    }
}
"""

def test_incomplete_pausable_fires(sa):
    res = _analyze(sa, _PAUSABLE_POSITIVE)
    hits = _titled(_real(res), "Incomplete pausable")
    assert len(hits) >= 1, f"Expected incomplete pausable, got: {[f.title for f in _real(res)]}"

def test_incomplete_pausable_clean(sa):
    res = _analyze(sa, _PAUSABLE_NEGATIVE)
    hits = _titled(_real(res), "Incomplete pausable")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 6. ERC4626 rounding direction
# ---------------------------------------------------------------------------

_ERC4626_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 totalSupply;
    uint256 totalAssets;
    function previewWithdraw(uint256 assets) public view returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
    }
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
    }
}
"""

_ERC4626_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 totalSupply;
    uint256 totalAssets;
    function previewWithdraw(uint256 assets) public view returns (uint256 shares) {
        shares = (assets * totalSupply + totalAssets - 1) / totalAssets;
    }
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets;
    }
}
"""

def test_erc4626_rounding_fires(sa):
    res = _analyze(sa, _ERC4626_POSITIVE)
    hits = _titled(_real(res), "ERC4626")
    assert len(hits) >= 1, f"Expected ERC4626 rounding finding, got: {[f.title for f in _real(res)]}"

def test_erc4626_rounding_clean(sa):
    res = _analyze(sa, _ERC4626_NEGATIVE)
    hits = _titled(_real(res), "ERC4626")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 7. Rebasing token accounting
# ---------------------------------------------------------------------------

_REBASING_POSITIVE = """
pragma solidity ^0.8.0;
interface IStETH { function transfer(address, uint256) external; }
contract LidoVault {
    IStETH public stETH;
    mapping(address => uint256) public deposited;
    function stake(uint256 amount) external {
        deposited[msg.sender] += amount;
    }
    function withdraw() external {
        uint256 amt = deposited[msg.sender];
        deposited[msg.sender] = 0;
        stETH.transfer(msg.sender, amt);
    }
}
"""

_REBASING_NEGATIVE = """
pragma solidity ^0.8.0;
interface IStETH { function transfer(address, uint256) external; function balanceOf(address) external view returns (uint256); }
contract LidoVault {
    IStETH public stETH;
    uint256 public totalShares;
    mapping(address => uint256) public userShares;
    function stake(uint256 amount) external {
        uint256 poolBal = stETH.balanceOf(address(this));
        uint256 newShares = totalShares == 0 ? amount : amount * totalShares / poolBal;
        userShares[msg.sender] += newShares;
        totalShares += newShares;
    }
    function withdraw() external {
        uint256 poolBal = stETH.balanceOf(address(this));
        uint256 amt = userShares[msg.sender] * poolBal / totalShares;
        userShares[msg.sender] = 0;
        stETH.transfer(msg.sender, amt);
    }
}
"""

def test_rebasing_token_fires(sa):
    res = _analyze(sa, _REBASING_POSITIVE)
    hits = _titled(_real(res), "Rebasing token")
    assert len(hits) >= 1, f"Expected rebasing token finding, got: {[f.title for f in _real(res)]}"

def test_rebasing_token_clean(sa):
    res = _analyze(sa, _REBASING_NEGATIVE)
    hits = _titled(_real(res), "Rebasing token")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 8. receive() / fallback() extraction
# ---------------------------------------------------------------------------

_RECEIVE_FALLBACK_SRC = """
pragma solidity ^0.8.0;
contract Bank {
    mapping(address => uint256) balances;
    function withdraw(uint256 amt) external {
        (bool ok,) = msg.sender.call{value: amt}("");
        balances[msg.sender] -= amt;
    }
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
    fallback() external payable {}
}
"""

def test_receive_fallback_extracted(sa):
    fns = sa._extract_functions(_RECEIVE_FALLBACK_SRC)
    names = {f['name'] for f in fns}
    assert 'receive' in names, f"receive() not extracted; got: {names}"
    assert 'fallback' in names, f"fallback() not extracted; got: {names}"


# ---------------------------------------------------------------------------
# 9. Yul block stripping (no FP on safe OZ proxy pattern)
# ---------------------------------------------------------------------------

_YUL_PROXY = """
pragma solidity ^0.8.0;
contract Proxy {
    address immutable _impl;
    constructor(address impl_) { _impl = impl_; }
    fallback() external payable {
        address impl = _impl;
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
"""

def test_yul_proxy_no_delegatecall_fp(sa):
    res = _analyze(sa, _YUL_PROXY)
    dc_hits = [f for f in _real(res) if 'delegatecall' in f.title.lower() and 'injection' in f.title.lower()]
    assert len(dc_hits) == 0, f"FP on Yul proxy: {[f.title for f in dc_hits]}"


# ---------------------------------------------------------------------------
# 10. Interprocedural accrual-gate (call chain A -> B -> accrual)
# ---------------------------------------------------------------------------

_INTERPROCEDURAL_SRC = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public rate;
    uint256 public started;
    function mintInflation() public {
        uint256 amt = totalSupply() * rate;
        require(amt > 0, "NoMintableAmount");
    }
    function _checkAndAccrue() internal {
        if (started != 0) mintInflation();
    }
    function updateRate(uint256 newRate) external onlyOwner {
        _checkAndAccrue();
        rate = newRate;
    }
    modifier onlyOwner() { _; }
    function totalSupply() internal view returns (uint256) { return 1e18; }
}
"""

def test_interprocedural_accrual_gate(sa):
    res = _analyze(sa, _INTERPROCEDURAL_SRC)
    hits = _titled(_real(res), "Accrual-gate")
    assert len(hits) >= 1, f"Interprocedural accrual-gate missed; got: {[f.title for f in _real(res)]}"


# ---------------------------------------------------------------------------
# 11. Timestamp dependency
# ---------------------------------------------------------------------------

_TIMESTAMP_POSITIVE = """
pragma solidity ^0.8.0;
contract Lottery {
    function pickWinner(uint256 numPlayers) external returns (uint256) {
        return uint256(keccak256(abi.encode(block.timestamp, msg.sender))) % numPlayers;
    }
}
"""

_TIMESTAMP_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vesting {
    uint256 public start;
    constructor() { start = block.timestamp; }
    function claim() external {
        require(block.timestamp >= start + 365 days);
    }
}
"""

def test_timestamp_dependency_fires(sa):
    res = _analyze(sa, _TIMESTAMP_POSITIVE)
    hits = _titled(_real(res), "Timestamp")
    assert len(hits) >= 1, f"Expected timestamp finding, got: {[f.title for f in _real(res)]}"

def test_timestamp_dependency_clean(sa):
    res = _analyze(sa, _TIMESTAMP_NEGATIVE)
    hits = _titled(_real(res), "Timestamp manipulation")
    assert len(hits) == 0, f"False positive on vesting: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 12. Stale oracle
# ---------------------------------------------------------------------------

_ORACLE_POSITIVE = """
pragma solidity ^0.8.0;
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    );
}
contract PriceFeed {
    AggregatorV3Interface feed;
    function getPrice() external view returns (int256) {
        (, int256 price,,,) = feed.latestRoundData();
        return price;
    }
}
"""

_ORACLE_NEGATIVE = """
pragma solidity ^0.8.0;
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256 updatedAt, uint80
    );
}
contract PriceFeed {
    AggregatorV3Interface feed;
    uint256 constant MAX_STALENESS = 3600;
    function getPrice() external view returns (int256) {
        (, int256 price,,uint256 updatedAt,) = feed.latestRoundData();
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale");
        return price;
    }
}
"""

def test_stale_oracle_fires(sa):
    res = _analyze(sa, _ORACLE_POSITIVE)
    hits = _titled(_real(res), "oracle")
    assert len(hits) >= 1, f"Expected oracle finding, got: {[f.title for f in _real(res)]}"

def test_stale_oracle_clean(sa):
    res = _analyze(sa, _ORACLE_NEGATIVE)
    hits = _titled(_real(res), "Stale oracle")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 13. Critical address swap without drain
# ---------------------------------------------------------------------------

_ADDR_SWAP_POSITIVE = """
pragma solidity ^0.8.0;
contract Protocol {
    address public vault;
    function setVault(address newVault) external onlyOwner {
        vault = newVault;
    }
    modifier onlyOwner() { _; }
}
"""

_ADDR_SWAP_NEGATIVE = """
pragma solidity ^0.8.0;
contract Protocol {
    address public vault;
    function setVault(address newVault) external onlyOwner {
        _drainVault(vault);
        vault = newVault;
    }
    function _drainVault(address v) internal {}
    modifier onlyOwner() { _; }
}
"""

def test_critical_address_swap_fires(sa):
    res = _analyze(sa, _ADDR_SWAP_POSITIVE)
    hits = _titled(_real(res), "Critical address swap")
    assert len(hits) >= 1, f"Expected address swap finding, got: {[f.title for f in _real(res)]}"

def test_critical_address_swap_clean(sa):
    res = _analyze(sa, _ADDR_SWAP_NEGATIVE)
    hits = _titled(_real(res), "Critical address swap")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 14. DERC20 regression — the original audit finding must still fire
# ---------------------------------------------------------------------------

import os as _os

_DERC20_PATH = _os.path.join(
    _os.path.dirname(__file__), "..", "..",
    "doppler-contracts", "src", "tokens", "DERC20.sol"
)

@pytest.mark.skipif(not _os.path.exists(_DERC20_PATH), reason="doppler-contracts not available")
def test_derc20_accrual_gate_regression(sa):
    with open(_DERC20_PATH, encoding="utf-8") as fh:
        src = fh.read()
    res = sa.analyze(src, use_slither=False, use_ast=False)
    hits = _titled([f for f in res.findings if not f.is_false_positive], "Accrual-gate")
    assert len(hits) >= 1, "DERC20 regression: accrual-gate DoS not detected"
    assert hits[0].severity == StaticSeverity.HIGH


# ===========================================================================
# v1.7 NEW DETECTOR TESTS (11 detectors × 2 cases = 22 tests)
# ===========================================================================

# ---------------------------------------------------------------------------
# 15. Unprotected initialize()
# ---------------------------------------------------------------------------

_INIT_POSITIVE = """
pragma solidity ^0.8.0;
contract Proxy {
    address public owner;
    bool public paused;
    function initialize(address _owner) external {
        owner = _owner;
        paused = false;
    }
}
"""

_INIT_NEGATIVE = """
pragma solidity ^0.8.0;
contract Proxy {
    address public owner;
    bool private _initialized;
    function initialize(address _owner) external {
        require(!_initialized, "already initialized");
        _initialized = true;
        owner = _owner;
    }
}
"""

def test_unprotected_initialize_fires(sa):
    res = _analyze(sa, _INIT_POSITIVE)
    hits = _titled(_real(res), "Unprotected initializer")
    assert len(hits) >= 1, f"Expected init finding, got: {[f.title for f in _real(res)]}"

def test_unprotected_initialize_clean(sa):
    res = _analyze(sa, _INIT_NEGATIVE)
    hits = _titled(_real(res), "Unprotected initializer")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 16. tx.origin authentication
# ---------------------------------------------------------------------------

_TXORIGIN_POSITIVE = """
pragma solidity ^0.8.0;
contract Wallet {
    address owner;
    function transfer(address to, uint256 amt) external {
        require(tx.origin == owner, "not owner");
        payable(to).transfer(amt);
    }
}
"""

_TXORIGIN_NEGATIVE = """
pragma solidity ^0.8.0;
contract Wallet {
    address owner;
    // EOA-only check: tx.origin == msg.sender prevents contract callers
    function transfer(address to, uint256 amt) external {
        require(msg.sender == owner, "not owner");
        require(tx.origin == msg.sender, "no contracts");
        payable(to).transfer(amt);
    }
}
"""

def test_tx_origin_auth_fires(sa):
    res = _analyze(sa, _TXORIGIN_POSITIVE)
    hits = _titled(_real(res), "tx.origin")
    assert len(hits) >= 1, f"Expected tx.origin finding, got: {[f.title for f in _real(res)]}"

def test_tx_origin_auth_clean(sa):
    res = _analyze(sa, _TXORIGIN_NEGATIVE)
    # Old "tx.origin as auth" detector should NOT fire (has msg.sender == owner).
    # EIP-7702 detector WILL fire on tx.origin == msg.sender (that's correct).
    old_auth_hits = [f for f in _real(res)
                     if "tx.origin" in f.title.lower() and "eip-7702" not in f.title.lower()]
    assert len(old_auth_hits) == 0, f"False positive (old auth): {[f.title for f in old_auth_hits]}"


# ---------------------------------------------------------------------------
# 17. Spot price oracle (getReserves)
# ---------------------------------------------------------------------------

_SPOT_PRICE_POSITIVE = """
pragma solidity ^0.8.0;
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}
contract PriceOracle {
    IUniswapV2Pair pair;
    function getPrice() external view returns (uint256 price) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        price = uint256(reserve1) * 1e18 / uint256(reserve0);
    }
}
"""

_SPOT_PRICE_NEGATIVE = """
pragma solidity ^0.8.0;
interface IUniswapV2Pair {
    function price0CumulativeLast() external view returns (uint256);
    function price1CumulativeLast() external view returns (uint256);
}
contract TWAPOracle {
    IUniswapV2Pair pair;
    uint256 price0CumulativeLast;
    uint256 price1CumulativeLast;
    uint32 blockTimestampLast;
    uint256 public price;
    function update() external {
        uint256 price0Cumulative = pair.price0CumulativeLast();
        uint256 timeElapsed = block.timestamp - blockTimestampLast;
        price = (price0Cumulative - price0CumulativeLast) / timeElapsed;
    }
}
"""

def test_spot_price_oracle_fires(sa):
    res = _analyze(sa, _SPOT_PRICE_POSITIVE)
    hits = _titled(_real(res), "Spot price oracle")
    assert len(hits) >= 1, f"Expected spot price finding, got: {[f.title for f in _real(res)]}"

def test_spot_price_oracle_clean(sa):
    res = _analyze(sa, _SPOT_PRICE_NEGATIVE)
    hits = _titled(_real(res), "Spot price oracle")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 18. Signature replay (no nonce)
# ---------------------------------------------------------------------------

_SIG_REPLAY_POSITIVE = """
pragma solidity ^0.8.0;
contract Permit {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amt, bytes memory sig) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amt));
        address signer = ecrecover(hash, uint8(sig[0]), bytes32(sig[1:33]), bytes32(sig[33:65]));
        require(signer != address(0), "bad sig");
        balances[signer] -= amt;
        balances[to] += amt;
    }
}
"""

_SIG_REPLAY_NEGATIVE = """
pragma solidity ^0.8.0;
contract Permit {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    function transfer(address to, uint256 amt, uint256 nonce, bytes memory sig) external {
        require(nonces[msg.sender] == nonce, "bad nonce");
        bytes32 hash = keccak256(abi.encodePacked(to, amt, nonce));
        address signer = ecrecover(hash, uint8(sig[0]), bytes32(sig[1:33]), bytes32(sig[33:65]));
        require(signer != address(0), "bad sig");
        nonces[signer]++;
        balances[signer] -= amt;
        balances[to] += amt;
    }
}
"""

def test_signature_replay_fires(sa):
    res = _analyze(sa, _SIG_REPLAY_POSITIVE)
    hits = _titled(_real(res), "Signature replay")
    assert len(hits) >= 1, f"Expected sig replay finding, got: {[f.title for f in _real(res)]}"

def test_signature_replay_clean(sa):
    res = _analyze(sa, _SIG_REPLAY_NEGATIVE)
    hits = _titled(_real(res), "Signature replay")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 19. Missing slippage protection
# ---------------------------------------------------------------------------

_SLIPPAGE_POSITIVE = """
pragma solidity ^0.8.0;
interface IRouter {
    function swapExactTokensForTokens(
        uint amountIn, uint amountOutMin, address[] calldata path,
        address to, uint deadline
    ) external returns (uint[] memory);
}
contract Compounder {
    IRouter router;
    address[] path;
    function compound(uint amt) external {
        router.swapExactTokensForTokens(amt, 0, path, address(this), block.timestamp);
    }
}
"""

_SLIPPAGE_NEGATIVE = """
pragma solidity ^0.8.0;
interface IRouter {
    function swapExactTokensForTokens(
        uint amountIn, uint amountOutMin, address[] calldata path,
        address to, uint deadline
    ) external returns (uint[] memory);
}
contract Compounder {
    IRouter router;
    address[] path;
    function compound(uint amt, uint minAmountOut) external {
        router.swapExactTokensForTokens(amt, minAmountOut, path, address(this), block.timestamp + 300);
    }
}
"""

def test_missing_slippage_fires(sa):
    res = _analyze(sa, _SLIPPAGE_POSITIVE)
    hits = _titled(_real(res), "slippage")
    assert len(hits) >= 1, f"Expected slippage finding, got: {[f.title for f in _real(res)]}"

def test_missing_slippage_clean(sa):
    res = _analyze(sa, _SLIPPAGE_NEGATIVE)
    hits = _titled(_real(res), "slippage")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 20. Ether lock
# ---------------------------------------------------------------------------

_ETHER_LOCK_POSITIVE = """
pragma solidity ^0.8.0;
contract Staker {
    mapping(address => uint256) public stakes;
    receive() external payable {
        stakes[msg.sender] += msg.value;
    }
    // No withdraw function — ETH is locked forever
}
"""

_ETHER_LOCK_NEGATIVE = """
pragma solidity ^0.8.0;
contract Staker {
    mapping(address => uint256) public stakes;
    receive() external payable {
        stakes[msg.sender] += msg.value;
    }
    function withdraw(uint256 amt) external {
        require(stakes[msg.sender] >= amt);
        stakes[msg.sender] -= amt;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
"""

def test_ether_lock_fires(sa):
    res = _analyze(sa, _ETHER_LOCK_POSITIVE)
    hits = _titled(_real(res), "Ether lock")
    assert len(hits) >= 1, f"Expected ether lock finding, got: {[f.title for f in _real(res)]}"

def test_ether_lock_clean(sa):
    res = _analyze(sa, _ETHER_LOCK_NEGATIVE)
    hits = _titled(_real(res), "Ether lock")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 21. Division by zero risk
# ---------------------------------------------------------------------------

_DIV_ZERO_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;
    function previewRedeem(uint256 sharesToBurn) external view returns (uint256) {
        return sharesToBurn * totalAssets / totalShares;
    }
}
"""

_DIV_ZERO_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalShares;
    uint256 public totalAssets;
    function previewRedeem(uint256 sharesToBurn) external view returns (uint256) {
        if (totalShares == 0) return 0;
        return sharesToBurn * totalAssets / totalShares;
    }
}
"""

def test_division_by_zero_fires(sa):
    res = _analyze(sa, _DIV_ZERO_POSITIVE)
    hits = _titled(_real(res), "Division-by-zero")
    assert len(hits) >= 1, f"Expected div-by-zero finding, got: {[f.title for f in _real(res)]}"

def test_division_by_zero_clean(sa):
    res = _analyze(sa, _DIV_ZERO_NEGATIVE)
    hits = _titled(_real(res), "Division-by-zero")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 22. Hardcoded 18-decimal assumption
# ---------------------------------------------------------------------------

_DECIMAL_POSITIVE = """
pragma solidity ^0.8.0;
interface IERC20 { function transferFrom(address,address,uint256) external returns(bool); }
contract Vault {
    IERC20 token;
    uint256 totalDeposited;
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 shares = amount * 1e18 / totalDeposited;
        totalDeposited += amount;
    }
}
"""

_DECIMAL_NEGATIVE = """
pragma solidity ^0.8.0;
interface IERC20 {
    function transferFrom(address,address,uint256) external returns(bool);
    function decimals() external view returns (uint8);
}
contract Vault {
    IERC20 token;
    uint8 TOKEN_DECIMALS;
    uint256 PRECISION;
    uint256 totalDeposited;
    constructor(address _token) {
        token = IERC20(_token);
        TOKEN_DECIMALS = token.decimals();
        PRECISION = 10 ** TOKEN_DECIMALS;
    }
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 shares = amount * PRECISION / totalDeposited;
        totalDeposited += amount;
    }
}
"""

def test_hardcoded_decimals_fires(sa):
    res = _analyze(sa, _DECIMAL_POSITIVE)
    hits = _titled(_real(res), "18-decimal")
    assert len(hits) >= 1, f"Expected decimal finding, got: {[f.title for f in _real(res)]}"

def test_hardcoded_decimals_clean(sa):
    res = _analyze(sa, _DECIMAL_NEGATIVE)
    hits = _titled(_real(res), "18-decimal")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 23. Selfdestruct ETH injection
# ---------------------------------------------------------------------------

_SD_INJECT_POSITIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalShares;
    function getVirtualPrice() external view returns (uint256) {
        return address(this).balance * 1e18 / totalShares;
    }
    receive() external payable {}
}
"""

_SD_INJECT_NEGATIVE = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalShares;
    uint256 private _ethBalance;
    function getVirtualPrice() external view returns (uint256) {
        return _ethBalance * 1e18 / totalShares;
    }
    receive() external payable { _ethBalance += msg.value; }
}
"""

def test_selfdestruct_injection_fires(sa):
    res = _analyze(sa, _SD_INJECT_POSITIVE)
    hits = _titled(_real(res), "Selfdestruct ETH injection")
    assert len(hits) >= 1, f"Expected selfdestruct injection finding, got: {[f.title for f in _real(res)]}"

def test_selfdestruct_injection_clean(sa):
    res = _analyze(sa, _SD_INJECT_NEGATIVE)
    hits = _titled(_real(res), "Selfdestruct ETH injection")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 24. Cross-chain message validation
# ---------------------------------------------------------------------------

_CCMSG_POSITIVE = """
pragma solidity ^0.8.0;
contract BridgeReceiver {
    mapping(address => uint256) public balances;
    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 _nonce,
        bytes calldata _payload
    ) external {
        (address user, uint256 amount) = abi.decode(_payload, (address, uint256));
        balances[user] += amount;
    }
}
"""

_CCMSG_NEGATIVE = """
pragma solidity ^0.8.0;
contract BridgeReceiver {
    mapping(uint16 => bytes) public trustedRemote;
    mapping(address => uint256) public balances;
    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 _nonce,
        bytes calldata _payload
    ) external {
        require(
            keccak256(trustedRemote[_srcChainId]) == keccak256(_srcAddress),
            "untrusted source"
        );
        (address user, uint256 amount) = abi.decode(_payload, (address, uint256));
        balances[user] += amount;
    }
}
"""

def test_cross_chain_msg_fires(sa):
    res = _analyze(sa, _CCMSG_POSITIVE)
    hits = _titled(_real(res), "Cross-chain callback")
    assert len(hits) >= 1, f"Expected cross-chain finding, got: {[f.title for f in _real(res)]}"

def test_cross_chain_msg_clean(sa):
    res = _analyze(sa, _CCMSG_NEGATIVE)
    hits = _titled(_real(res), "Cross-chain callback")
    assert len(hits) == 0, f"False positive: {[f.title for f in hits]}"


# ---------------------------------------------------------------------------
# 25. Unsafe selfdestruct
# ---------------------------------------------------------------------------

_UNSAFE_SD_POSITIVE = """
pragma solidity ^0.8.0;
contract Library {
    address public owner;
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
"""

_UNSAFE_SD_NEGATIVE = """
pragma solidity ^0.8.0;
contract Library {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function kill() external onlyOwner {
        selfdestruct(payable(owner));
    }
}
"""

def test_unsafe_selfdestruct_fires(sa):
    res = _analyze(sa, _UNSAFE_SD_POSITIVE)
    hits = _titled(_real(res), "Unguarded selfdestruct")
    assert len(hits) >= 1, f"Expected selfdestruct finding, got: {[f.title for f in _real(res)]}"

def test_unsafe_selfdestruct_clean(sa):
    res = _analyze(sa, _UNSAFE_SD_NEGATIVE)
    # Guarded selfdestruct is MEDIUM severity, not a clear FP — just check HIGH not present
    high_hits = [f for f in _titled(_real(res), "Unguarded selfdestruct")
                 if f.severity == StaticSeverity.HIGH]
    assert len(high_hits) == 0, f"False positive HIGH selfdestruct: {[f.title for f in high_hits]}"


# ---------------------------------------------------------------------------
# EIP-7702 (Pectra, May 2025) — new vulnerability class
# ---------------------------------------------------------------------------

_EIP7702_POSITIVE = """
pragma solidity ^0.8.0;
contract VulnerableVault {
    mapping(address => uint256) public balances;

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "no contracts");
        _;
    }

    function deposit() external payable onlyEOA {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(!msg.sender.isContract(), "EOA only");
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

_EIP7702_NEGATIVE = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    mapping(address => bool) public allowlist;

    function deposit() external payable {
        require(allowlist[msg.sender], "not allowed");
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

def test_eip7702_tx_origin_fires(sa):
    res = _analyze(sa, _EIP7702_POSITIVE)
    hits = _titled(_real(res), "EIP-7702")
    assert len(hits) >= 1, f"Expected EIP-7702 finding, got: {[f.title for f in _real(res)]}"

def test_eip7702_clean(sa):
    res = _analyze(sa, _EIP7702_NEGATIVE)
    hits = _titled(_real(res), "EIP-7702")
    assert len(hits) == 0, f"False positive EIP-7702: {[f.title for f in hits]}"
