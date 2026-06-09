"""Root conftest.py — shared fixtures and path setup for all tests."""

import sys
import os
import importlib.util
import shutil
from pathlib import Path

import pytest

# Ensure src/ is on path for all test files
_SRC = str(Path(__file__).parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


_WEB3_TESTS = {
    "test_basic.py",
    "test_exploit.py",
    "test_explorer.py",
    "test_fuzzer.py",
    "test_monitor.py",
    "test_profiler.py",
    "test_trust_model_extraction.py",
}

_SOLC_TESTS = {
    "test_erc1155_invariants.py",
    "test_erc20_invariants.py",
    "test_erc4626_invariants.py",
    "test_erc721_invariants.py",
}


# Tests that need a live RPC endpoint (not just the web3 library). Skipped when
# RPC_URL is unset so CI stays green without network access; set RPC_URL to run.
_RPC_TESTS = _WEB3_TESTS | {
    "test_taint_analysis_trusted.py",
    "test_taint_analysis_untrusted.py",
}


def pytest_ignore_collect(collection_path, config):
    """Skip optional-tool / network test modules before import-time checks run."""
    path = Path(str(collection_path))
    name = path.name
    if name in _WEB3_TESTS and importlib.util.find_spec("web3") is None:
        return True
    if name in _RPC_TESTS and not os.environ.get("RPC_URL"):
        return True
    if name in _SOLC_TESTS and shutil.which("solc") is None:
        return True
    return False


@pytest.fixture
def tmp_sol_project(tmp_path):
    """Minimal Solidity project with a vulnerable contract."""
    (tmp_path / "Vault.sol").write_text("""
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 a) external {
        require(balances[msg.sender] >= a);
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] -= a;
    }
}
""")
    return tmp_path


@pytest.fixture
def tmp_noir_project(tmp_path):
    """Minimal Noir project with main.nr."""
    (tmp_path / "Nargo.toml").write_text('[package]\nname="test"\ntype="bin"\n')
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.nr").write_text("""
fn main(x: Field, y: Field) -> pub Field {
    assert(x != 0);
    let result = x + y;
    result
}
""")
    return tmp_path


@pytest.fixture
def tmp_aztec_project(tmp_path):
    """Minimal Aztec.nr project."""
    (tmp_path / "Nargo.toml").write_text(
        '[package]\nname="test_aztec"\ntype="contract"\n'
        '[dependencies]\naztec = { path = "../aztec-nr" }\n'
    )
    src = tmp_path / "src"
    src.mkdir()
    return tmp_path
