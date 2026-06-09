"""
Tests for ChainEDR Hunter — Checks 15, 16, 17

Check 15: Read-Only Reentrancy (Curve-style view inconsistency)
Check 16: Sandwich Attack / Oracle Manipulation (slot0, zero slippage)
Check 17: Permit / EIP-2612 Attack Surface (replay, front-run, deadline)

All tests use mock data — no real RPC calls.
"""

import pytest
from unittest.mock import MagicMock
from chainedr.hunter import Hunter, Finding


# ──────────────────────────────────────────────────────────
# Shared fixture: Hunter instance with mocked Web3
# ──────────────────────────────────────────────────────────

@pytest.fixture
def hunter():
    h = Hunter.__new__(Hunter)
    h.rpc_url = "http://localhost:8545"
    h.w3 = MagicMock()
    h.w3.is_connected.return_value = True
    h.findings = []
    return h


# ══════════════════════════════════════════════════════════
# CHECK 15: Read-Only Reentrancy
# ══════════════════════════════════════════════════════════

CURVE_POOL_ABI = [
    {
        "name": "get_virtual_price",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "remove_liquidity",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "amount", "type": "uint256"}],
        "outputs": [],
    },
]

CURVE_SOURCE = {
    "remove_liquidity": (
        "function remove_liquidity(uint256 amount) external {\n"
        "    // send ETH to caller before updating reserves\n"
        "    msg.sender.call{value: ethOut}('');\n"
        "    reserves[0] -= tokenOut0;\n"
        "    reserves[1] -= tokenOut1;\n"
        "}"
    ),
    "get_virtual_price": (
        "function get_virtual_price() external view returns (uint256) {\n"
        "    return totalSupply * 1e18 / reserves[0];\n"
        "}"
    ),
}


def test_readonly_reentrancy_detected(hunter):
    """Check #15: Curve-style pool should trigger read-only reentrancy."""
    contract_info = {"functions": CURVE_POOL_ABI, "source_code": CURVE_SOURCE}
    results = hunter._check_readonly_reentrancy(contract_info)

    assert len(results) >= 1
    r = results[0]
    assert r["check"] == "readonly_reentrancy"
    assert r["check_number"] == 15
    assert r["severity"] == "HIGH"
    assert "get_virtual_price" in r["function"]
    assert "remove_liquidity" in r["description"]
    assert r["confidence"] >= 0.6


def test_readonly_reentrancy_no_fp_without_external_call(hunter):
    """Check #15: No external calls = no finding (no false positive)."""
    safe_source = {
        "remove_liquidity": (
            "function remove_liquidity(uint256 amount) external {\n"
            "    balances[msg.sender] -= amount;\n"  # state update only, no external call
            "}"
        ),
        "get_virtual_price": "function get_virtual_price() external view returns (uint256) {}",
    }
    contract_info = {"functions": CURVE_POOL_ABI, "source_code": safe_source}
    results = hunter._check_readonly_reentrancy(contract_info)
    assert len(results) == 0


def test_readonly_reentrancy_no_fp_without_price_view(hunter):
    """Check #15: No view price function = no finding."""
    generic_abi = [
        {
            "name": "getBalance",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "uint256"}],
        },
    ]
    contract_info = {"functions": generic_abi, "source_code": CURVE_SOURCE}
    results = hunter._check_readonly_reentrancy(contract_info)
    assert len(results) == 0


# ══════════════════════════════════════════════════════════
# CHECK 16: Sandwich / Oracle Manipulation
# ══════════════════════════════════════════════════════════

SLOT0_SOURCE = {
    "getPrice": (
        "function getPrice() internal view returns (uint256) {\n"
        "    (uint160 sqrtPriceX96,,,,,,) = pool.slot0();\n"
        "    return uint256(sqrtPriceX96);\n"
        "}"
    ),
    "swap": "function swap(address tokenIn, uint256 amountIn) external {}",
}

TWAP_SOURCE = {
    "getPrice": (
        "function getPrice() internal view returns (uint256) {\n"
        "    return OracleLibrary.consult(pool, twapInterval);\n"
        "}"
    ),
    "swap": "function swap(address tokenIn, uint256 amountIn) external {}",
}

ZERO_SLIP_SOURCE = {
    "doSwap": (
        "function doSwap(uint256 amount) external {\n"
        "    router.exactInputSingle(ISwapRouter.ExactInputSingleParams({\n"
        "        tokenIn: WETH, tokenOut: USDC, amountIn: amount,\n"
        "        amountOutMinimum: 0,\n"
        "        sqrtPriceLimitX96: 0\n"
        "    }));\n"
        "}"
    ),
}


def test_sandwich_detected_spot_price(hunter):
    """Check #16: slot0 usage without TWAP should trigger oracle manipulation finding."""
    contract_info = {"functions": [], "source_code": SLOT0_SOURCE}
    results = hunter._check_sandwich_vulnerability(contract_info)

    checks = {r["check"] for r in results}
    assert "oracle_manipulation" in checks

    oracle = next(r for r in results if r["check"] == "oracle_manipulation")
    assert oracle["severity"] == "HIGH"
    assert oracle["check_number"] == 16
    assert oracle["confidence"] >= 0.7
    assert "slot0" in oracle["description"].lower() or "sqrtPriceX96" in oracle["description"]


def test_sandwich_no_fp_on_twap(hunter):
    """Check #16: TWAP usage should NOT trigger oracle manipulation finding."""
    contract_info = {"functions": [], "source_code": TWAP_SOURCE}
    results = hunter._check_sandwich_vulnerability(contract_info)

    checks = {r["check"] for r in results}
    assert "oracle_manipulation" not in checks


def test_sandwich_detected_zero_slippage(hunter):
    """Check #16b: amountOutMinimum = 0 should trigger slippage finding."""
    contract_info = {"functions": [], "source_code": ZERO_SLIP_SOURCE}
    results = hunter._check_sandwich_vulnerability(contract_info)

    checks = {r["check"] for r in results}
    assert "missing_slippage_protection" in checks

    slippage = next(r for r in results if r["check"] == "missing_slippage_protection")
    assert slippage["severity"] == "MEDIUM"
    assert slippage["confidence"] >= 0.75


def test_sandwich_no_fp_on_clean_source(hunter):
    """Check #16: Clean source with no AMM reads = no findings."""
    clean_source = {
        "transfer": "function transfer(address to, uint256 amount) external { balances[to] += amount; }",
    }
    contract_info = {"functions": [], "source_code": clean_source}
    results = hunter._check_sandwich_vulnerability(contract_info)
    assert len(results) == 0


# ══════════════════════════════════════════════════════════
# CHECK 17: Permit / EIP-2612 Attack Surface
# ══════════════════════════════════════════════════════════

INCOMPLETE_PERMIT_SOURCE = {
    "depositWithPermit": (
        "function depositWithPermit(uint256 amount, uint256 deadline,\n"
        "    uint8 v, bytes32 r, bytes32 s) external {\n"
        "    token.permit(msg.sender, address(this), amount, deadline, v, r, s);\n"
        "    token.transferFrom(msg.sender, address(this), amount);\n"
        "    balances[msg.sender] += amount;\n"
        "}"
    ),
}

BROKEN_PERMIT_IMPL_SOURCE = {
    "permit": (
        "function permit(address owner, address spender, uint256 value,\n"
        "    uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {\n"
        "    bytes32 digest = keccak256(abi.encodePacked(\n"
        "        DOMAIN_SEPARATOR, owner, spender, value, deadline));\n"
        "    address recoveredAddress = ecrecover(digest, v, r, s);\n"
        "    require(recoveredAddress == owner, 'Invalid signature');\n"
        "    _approve(owner, spender, value);\n"
        "}"
    ),
}

FULL_EIP2612_SOURCE = {
    "permit": (
        "function permit(address owner, address spender, uint256 value,\n"
        "    uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {\n"
        "    require(block.timestamp <= deadline, 'Permit expired');\n"
        "    nonces[owner]++;\n"
        "    bytes32 digest = keccak256(abi.encodePacked(\n"
        "        DOMAIN_SEPARATOR, owner, spender, value, nonces[owner], deadline));\n"
        "    address recoveredAddress = ecrecover(digest, v, r, s);\n"
        "    require(recoveredAddress == owner, 'Invalid signature');\n"
        "    _approve(owner, spender, value);\n"
        "}"
    ),
}

NO_PERMIT_SOURCE = {
    "transfer": "function transfer(address to, uint256 amount) external { balances[to] += amount; }",
}


def test_permit_missing_deadline(hunter):
    """Check #17a: permit without deadline check should trigger 17a."""
    contract_info = {"functions": [], "source_code": BROKEN_PERMIT_IMPL_SOURCE}
    results = hunter._check_permit_surface(contract_info)

    checks = {r["check"] for r in results}
    assert "permit_missing_deadline" in checks

    finding = next(r for r in results if r["check"] == "permit_missing_deadline")
    assert finding["severity"] == "MEDIUM"
    assert "17a" == str(finding["check_number"])


def test_permit_missing_nonce(hunter):
    """Check #17b: permit without nonce tracking should trigger 17b."""
    contract_info = {"functions": [], "source_code": BROKEN_PERMIT_IMPL_SOURCE}
    results = hunter._check_permit_surface(contract_info)

    checks = {r["check"] for r in results}
    assert "permit_missing_nonce" in checks

    finding = next(r for r in results if r["check"] == "permit_missing_nonce")
    assert finding["severity"] == "HIGH"
    assert finding["confidence"] >= 0.65


def test_permit_advisory_always_present(hunter):
    """Check #17c: advisory is emitted for permit implementations."""
    contract_info = {"functions": [], "source_code": BROKEN_PERMIT_IMPL_SOURCE}
    results = hunter._check_permit_surface(contract_info)

    checks = {r["check"] for r in results}
    assert "permit_frontrun_advisory" in checks

    advisory = next(r for r in results if r["check"] == "permit_frontrun_advisory")
    assert advisory["severity"] == "INFORMATIONAL"
    assert advisory["confidence"] >= 0.85


def test_permit_wrapper_call_not_treated_as_broken_implementation(hunter):
    """A wrapper calling token.permit() should not inherit token-side checks."""
    contract_info = {"functions": [], "source_code": INCOMPLETE_PERMIT_SOURCE}
    results = hunter._check_permit_surface(contract_info)

    checks = {r["check"] for r in results}
    assert "permit_missing_deadline" not in checks
    assert "permit_missing_nonce" not in checks


def test_permit_no_fp_on_complete_implementation(hunter):
    """Check #17: Full EIP-2612 implementation should only get advisory (17c), not 17a or 17b."""
    contract_info = {"functions": [], "source_code": FULL_EIP2612_SOURCE}
    results = hunter._check_permit_surface(contract_info)

    checks = {r["check"] for r in results}
    assert "permit_missing_deadline" not in checks
    assert "permit_missing_nonce" not in checks
    assert "permit_frontrun_advisory" in checks  # advisory is always present


def test_permit_no_fp_without_permit(hunter):
    """Check #17: Contract without permit = no findings at all."""
    contract_info = {"functions": [], "source_code": NO_PERMIT_SOURCE}
    results = hunter._check_permit_surface(contract_info)
    assert len(results) == 0


# ══════════════════════════════════════════════════════════
# Integration: dict_to_finding conversion
# ══════════════════════════════════════════════════════════

def test_dict_to_finding_conversion(hunter):
    """Ensure _dict_to_finding produces valid Finding objects."""
    d = {
        "check": "readonly_reentrancy",
        "check_number": 15,
        "function": "get_virtual_price",
        "severity": "HIGH",
        "confidence": 0.70,
        "description": "Test description",
        "recommendation": "Fix it",
        "cve_class": "READ_ONLY_REENTRANCY",
        "trust_level": "UNTRUSTED",
    }
    finding = hunter._dict_to_finding(d)
    assert isinstance(finding, Finding)
    assert finding.severity == "HIGH"
    assert finding.confidence == 0.70
    assert finding.exploitable is True  # HIGH => exploitable
    assert finding.trust_level == "UNTRUSTED"
    assert "15" in finding.title


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
