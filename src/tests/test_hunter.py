"""
Tests for ChainEDR Hunter — Module 8

Tests the zero-day hunting engine with mock data.
No real RPC calls — all tests use mocks.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from chainedr.hunter import Hunter, Finding, HuntReport


# ──────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────

SAMPLE_ABI = [
    # ERC4626 vault functions
    {"name": "deposit", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "assets", "type": "uint256"}, {"name": "receiver", "type": "address"}],
     "outputs": [{"name": "shares", "type": "uint256"}]},
    {"name": "withdraw", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "assets", "type": "uint256"}, {"name": "receiver", "type": "address"},
                {"name": "owner", "type": "address"}],
     "outputs": [{"name": "shares", "type": "uint256"}]},
    {"name": "redeem", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "shares", "type": "uint256"}, {"name": "receiver", "type": "address"},
                {"name": "owner", "type": "address"}],
     "outputs": [{"name": "assets", "type": "uint256"}]},
    {"name": "mint", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "shares", "type": "uint256"}, {"name": "receiver", "type": "address"}],
     "outputs": [{"name": "assets", "type": "uint256"}]},
    {"name": "totalAssets", "type": "function", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
    {"name": "convertToShares", "type": "function", "stateMutability": "view",
     "inputs": [{"name": "assets", "type": "uint256"}],
     "outputs": [{"name": "shares", "type": "uint256"}]},
    # Admin
    {"name": "owner", "type": "function", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "", "type": "address"}]},
    {"name": "setFee", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "fee", "type": "uint256"}], "outputs": []},
    # Callback
    {"name": "flashLoan", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"},
                {"name": "data", "type": "bytes"}], "outputs": []},
    # Swap without protections
    {"name": "swap", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "tokenIn", "type": "address"}, {"name": "amountIn", "type": "uint256"}],
     "outputs": []},
    # Oracle
    {"name": "getReserves", "type": "function", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "r0", "type": "uint256"}, {"name": "r1", "type": "uint256"}]},
    # Initialize
    {"name": "initialize", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "admin", "type": "address"}], "outputs": []},
    # Time lock
    {"name": "unlockTokens", "type": "function", "stateMutability": "nonpayable",
     "inputs": [], "outputs": []},
]


@pytest.fixture
def mock_w3():
    """Mock Web3 instance."""
    w3 = MagicMock()
    w3.is_connected.return_value = True
    w3.eth.chain_id = 1
    w3.eth.block_number = 20000000
    w3.eth.get_balance.return_value = 1000000000000000000  # 1 ETH
    w3.eth.get_storage_at.return_value = b'\x00' * 32
    w3.eth.get_code.return_value = b'\x60\x80\x60\x40'
    w3.eth.call.side_effect = Exception("revert")  # Default: calls revert
    return w3


@pytest.fixture
def hunter(mock_w3):
    """Hunter instance with mocked Web3."""
    with patch('chainedr.hunter.Web3') as MockWeb3:
        MockWeb3.HTTPProvider.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_instance.is_connected.return_value = True
        mock_instance.eth = mock_w3.eth
        MockWeb3.return_value = mock_instance
        MockWeb3.to_checksum_address = lambda x: x
        MockWeb3.keccak = lambda text='': b'\x00' * 32
        
        h = Hunter.__new__(Hunter)
        h.rpc_url = "http://localhost:8545"
        h.w3 = mock_instance
        h.w3.eth = mock_w3.eth
        h.findings = []
        return h


# ──────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────

def test_finding_dataclass():
    """Test 1: Finding data model."""
    f = Finding(
        severity="HIGH",
        title="Test finding",
        description="Description",
        function="swap",
        category="logic",
        confidence=0.8,
    )
    assert f.severity == "HIGH"
    assert f.confidence == 0.8
    assert f.exploitable == False


def test_hunt_report():
    """Test 2: HuntReport data model."""
    report = HuntReport(
        address="0x1234",
        chain_id=1,
        timestamp="2026-01-01",
        block_number=20000000,
        findings=[
            Finding(severity="CRITICAL", title="A", description="", function="f", category="c", confidence=0.9),
            Finding(severity="HIGH", title="B", description="", function="f", category="c", confidence=0.8),
            Finding(severity="MEDIUM", title="C", description="", function="f", category="c", confidence=0.7),
        ]
    )
    assert report.critical_count == 1
    assert report.high_count == 1
    assert len(report.findings) == 3


def test_attack_surface_mapping(hunter):
    """Test 3: Attack surface correctly identifies callbacks, flash loans, etc."""
    surface = hunter._map_attack_surface("0x1234", SAMPLE_ABI)
    
    assert "flashLoan" in surface["callbacks"]
    assert "flashLoan" in surface["flash_loan"]
    assert "swap" in surface["external_calls"]
    assert "deposit" in surface["external_calls"]


def test_erc4626_detection(hunter):
    """Test 4: ERC4626 vault inflation attack detection."""
    hunter._check_erc4626_vault("0x1234", SAMPLE_ABI)
    
    vault_findings = [f for f in hunter.findings if f.category == "vault"]
    assert len(vault_findings) >= 1
    
    inflation = [f for f in vault_findings if "inflation" in f.title.lower()]
    assert len(inflation) == 1
    assert inflation[0].severity == "MEDIUM"


def test_oracle_manipulation_detection(hunter):
    """Test 5: Oracle manipulation detected for getReserves."""
    hunter._check_oracle_dependency("0x1234", SAMPLE_ABI)
    
    oracle_findings = [f for f in hunter.findings if f.category == "oracle"]
    assert len(oracle_findings) >= 1
    assert oracle_findings[0].severity == "HIGH"
    assert oracle_findings[0].exploitable == True


def test_reentrancy_surface(hunter):
    """Test 6: Reentrancy surface found for callback functions."""
    hunter._check_reentrancy_surface("0x1234", SAMPLE_ABI)
    
    reent_findings = [f for f in hunter.findings if f.category == "reentrancy"]
    assert len(reent_findings) >= 1
    
    flash_reent = [f for f in reent_findings if "flashLoan" in f.title]
    assert len(flash_reent) == 1


def test_frontrunning_missing_slippage(hunter):
    """Test 7: Swap without slippage/deadline detected."""
    hunter._check_frontrunning_risk("0x1234", SAMPLE_ABI)
    
    fr_findings = [f for f in hunter.findings if f.category == "logic" and "swap" in f.function.lower()]
    assert len(fr_findings) >= 1
    
    no_slippage = [f for f in fr_findings if "slippage" in f.title.lower()]
    assert len(no_slippage) == 1
    assert no_slippage[0].severity == "HIGH"
    assert no_slippage[0].exploitable == True


def test_access_control_initializer(hunter):
    """Test 8: Callable initializer detected (when call doesn't revert)."""
    # Make initialize() NOT revert (= bug)
    hunter.w3.eth.call = MagicMock(return_value=b'\x00' * 32)
    
    hunter._check_access_control("0x1234", SAMPLE_ABI)
    
    ac_findings = [f for f in hunter.findings if f.category == "access_control"]
    assert len(ac_findings) >= 1
    assert ac_findings[0].severity == "CRITICAL"
    assert ac_findings[0].exploitable == True


def test_fee_on_transfer(hunter):
    """Test 9: Fee-on-transfer check for deposit functions."""
    hunter._check_fee_on_transfer("0x1234", SAMPLE_ABI)
    
    fot_findings = [f for f in hunter.findings if "fee-on-transfer" in f.title.lower()]
    assert len(fot_findings) == 1


def test_timestamp_dependency(hunter):
    """Test 10: Timestamp dependency detected."""
    hunter._check_timestamp_dependency("0x1234", SAMPLE_ABI)
    
    time_findings = [f for f in hunter.findings if "timestamp" in f.title.lower()]
    assert len(time_findings) == 1
    assert "unlocktokens" in time_findings[0].function.lower()


def test_permission_mapping(hunter):
    """Test 11: Permission mapping identifies admin functions."""
    perms = hunter._map_permissions("0x1234", SAMPLE_ABI)
    
    assert "setFee" in perms["admin_functions"]
    assert "swap" in perms["open_functions"]


def test_scan_source_directory_accepts_explicit_solidity_file(tmp_path):
    """Regression: direct .sol targets must not be treated as empty directories."""
    target = tmp_path / "CodeLengthGuard.sol"
    target.write_text(
        """
pragma solidity ^0.8.20;

contract CodeLengthGuard {
    function stakeForEOA(address user) external {
        require(user.code.length == 0, "EOA only");
    }
}
""",
        encoding="utf-8",
    )

    findings = Hunter.scan_source_directory(str(target), external_tools=False)

    assert any(f.get("check") == "AA7702-002" for f in findings)


def test_format_report(hunter):
    """Test 12: Report formatting."""
    report = HuntReport(
        address="0x1234",
        chain_id=1,
        timestamp="2026-01-01",
        block_number=20000000,
        findings=[
            Finding(severity="HIGH", title="Test", description="Desc",
                    function="f", category="c", confidence=0.8),
        ],
        attack_surface={"callbacks": ["flashLoan"]},
    )
    
    text = hunter.format_report(report)
    assert "ChainEDR Hunter Report" in text
    assert "0x1234" in text
    assert "[HIGH]" in text


def test_full_hunt(hunter):
    """Test 13: Full hunt pipeline runs without errors."""
    report = hunter.hunt("0x1234567890123456789012345678901234567890", SAMPLE_ABI)
    
    assert isinstance(report, HuntReport)
    assert len(report.findings) > 0
    assert report.address == "0x1234567890123456789012345678901234567890"
    assert report.chain_id == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
