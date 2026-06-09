"""Tests for the detector plugin interface, project context, and new detectors."""

import sys
import os
import tempfile
import shutil
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector_plugin import (
    Detector, DetectorCategory, Finding, ScanOptions, ScanResult, Severity,
    register_detector, get_all_detectors, discover_applicable, _REGISTRY,
)
from project_context import (
    discover_project, ProjectContext, ProjectType,
    _is_scannable_sol, _should_skip_dir,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_sol_project(tmp_path):
    """Create a minimal Solidity project."""
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
    (tmp_path / "Token.sol").write_text("""
pragma solidity ^0.8.0;
contract Token {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
""")
    return tmp_path


@pytest.fixture
def tmp_noir_project(tmp_path):
    """Create a minimal Noir project."""
    (tmp_path / "Nargo.toml").write_text("""
[package]
name = "test_circuit"
type = "bin"
""")
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.nr").write_text("""
fn main(x: Field, y: Field) -> pub Field {
    assert(x != 0);
    let result = x + y;
    result
}

unconstrained fn helper(a: Field) -> Field {
    a * 2
}

fn caller() {
    let val = helper(5);
    assert(val == 10);
}
""")
    return tmp_path


@pytest.fixture
def tmp_foundry_project(tmp_path):
    """Create a Foundry-style project."""
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n')
    src = tmp_path / "src"
    src.mkdir()
    (src / "Counter.sol").write_text("""
pragma solidity ^0.8.0;
contract Counter {
    uint256 public count;
    function increment() external { count += 1; }
}
""")
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "Counter.t.sol").write_text("// test file — should be skipped")
    return tmp_path


# ── ProjectContext tests ────────────────────────────────────────────────────

class TestProjectContext:
    def test_discover_solidity_bare(self, tmp_sol_project):
        ctx = discover_project(tmp_sol_project)
        assert ctx.has_solidity
        assert not ctx.has_noir
        assert not ctx.has_aztec
        assert ProjectType.SOLIDITY_BARE in ctx.project_types
        assert len(ctx.solidity_files) == 2

    def test_discover_foundry(self, tmp_foundry_project):
        ctx = discover_project(tmp_foundry_project)
        assert ctx.has_foundry
        assert ctx.foundry_root == tmp_foundry_project
        assert ProjectType.SOLIDITY_FOUNDRY in ctx.project_types
        # test files should be filtered
        assert all(".t.sol" not in f.name for f in ctx.solidity_files)
        assert len(ctx.solidity_files) == 1

    def test_discover_noir(self, tmp_noir_project):
        ctx = discover_project(tmp_noir_project)
        assert ctx.has_noir
        assert ctx.nargo_toml is not None
        assert ProjectType.NOIR in ctx.project_types
        assert len(ctx.noir_files) >= 1

    def test_discover_single_file(self, tmp_sol_project):
        sol = tmp_sol_project / "Vault.sol"
        ctx = discover_project(sol)
        assert len(ctx.solidity_files) == 1
        assert ctx.solidity_files[0] == sol

    def test_discover_empty(self, tmp_path):
        ctx = discover_project(tmp_path)
        assert ProjectType.UNKNOWN in ctx.project_types
        assert not ctx.has_solidity

    def test_skip_dirs(self):
        assert _should_skip_dir("node_modules")
        assert _should_skip_dir(".git")
        assert _should_skip_dir("DeFiHackLabs")
        assert not _should_skip_dir("src")
        assert not _should_skip_dir("contracts")

    def test_scannable_sol_filter(self, tmp_path):
        assert not _is_scannable_sol(tmp_path / "test" / "Foo.t.sol", tmp_path)
        assert not _is_scannable_sol(tmp_path / "script" / "Deploy.s.sol", tmp_path)
        assert _is_scannable_sol(tmp_path / "src" / "Vault.sol", tmp_path)

    def test_read_file_cache(self, tmp_sol_project):
        ctx = discover_project(tmp_sol_project)
        content1 = ctx.read_file(ctx.solidity_files[0])
        content2 = ctx.read_file(ctx.solidity_files[0])
        assert content1 is content2  # same object from cache

    def test_total_loc(self, tmp_sol_project):
        ctx = discover_project(tmp_sol_project)
        assert ctx.total_loc > 10

    def test_all_files(self, tmp_sol_project):
        ctx = discover_project(tmp_sol_project)
        assert len(ctx.all_files) == 2


# ── Detector Plugin Interface tests ─────────────────────────────────────────

class TestDetectorPlugin:
    def test_finding_to_dict(self):
        f = Finding(
            detector="test",
            rule_id="TEST-001",
            severity=Severity.HIGH,
            title="Test finding",
            description="A test",
            confidence=0.85,
        )
        d = f.to_dict()
        assert d["severity"] == "HIGH"
        assert d["confidence"] == 0.85
        assert d["detector"] == "test"
        assert d["analysis_depth"] == "static_heuristic"

    def test_finding_analysis_depth_from_semantic_context(self):
        f = Finding(
            detector="eip7702",
            rule_id="AA7702-001",
            severity=Severity.HIGH,
            title="Semantic finding",
            description="A semantic test",
            metadata={"semantic_context": {"analysis": "deep_ast"}},
        )

        assert f.analysis_depth() == "deep_ast"
        assert f.to_dict()["analysis_depth"] == "deep_ast"

    def test_finding_analysis_depth_from_external_tool(self):
        f = Finding(
            detector="solidity",
            rule_id="SL-reentrancy",
            severity=Severity.HIGH,
            title="Slither finding",
            description="An external tool finding",
        )

        assert f.analysis_depth() == "external_tool"

    def test_scan_result_by_severity(self):
        r = ScanResult(detector_name="test", findings=[
            Finding(detector="t", rule_id="1", severity=Severity.HIGH, title="a", description=""),
            Finding(detector="t", rule_id="2", severity=Severity.HIGH, title="b", description=""),
            Finding(detector="t", rule_id="3", severity=Severity.LOW, title="c", description=""),
        ])
        assert r.has_high
        assert r.has_critical is False
        assert r.by_severity() == {"HIGH": 2, "LOW": 1}

    def test_scan_options_defaults(self):
        opts = ScanOptions()
        assert opts.use_slither is True
        assert opts.use_ast is True
        assert opts.fail_on is None

    def test_registry(self):
        # Import builtins to register
        import detectors_builtin
        import eip7702_validation
        names = [d.name for d in get_all_detectors()]
        assert "solidity" in names
        assert "eip7702" in names
        assert "eip7702_validation" in names
        assert "bridge_zk" in names


# ── Built-in Detector Wrapper tests ─────────────────────────────────────────

class TestBuiltinDetectors:
    def test_slither_detector_no_slither(self, tmp_sol_project):
        import detectors_builtin
        ctx = discover_project(tmp_sol_project)
        det = detectors_builtin.SlitherDetector()
        assert det.discover(ctx) is True

        opts = ScanOptions(use_slither=False, use_ast=False)
        result = det._timed_scan(ctx, opts)
        assert result.error is not None
        assert "Slither not available" in result.error

    def test_eip7702_detector_on_vault(self, tmp_sol_project):
        import detectors_builtin
        ctx = discover_project(tmp_sol_project)
        det = detectors_builtin.EIP7702PluginDetector()
        opts = ScanOptions(use_slither=False, use_ast=False)
        result = det._timed_scan(ctx, opts)
        # Vault.sol has .transfer() + state-after-transfer → expanded 18-check catches it
        assert result.files_scanned >= 1
        assert any(f.rule_id in ("AA7702-003", "AA7702-014") for f in result.findings)

    def test_eip7702_detector_with_pattern(self, tmp_path):
        import detectors_builtin
        (tmp_path / "Wallet.sol").write_text("""
pragma solidity ^0.8.0;
contract Wallet {
    function isEOA(address a) public view returns (bool) {
        return a.code.length == 0;
    }
    function execute(address to) external {
        require(tx.origin == msg.sender, "not EOA");
        (bool ok,) = to.call("");
        require(ok);
    }
}
""")
        ctx = discover_project(tmp_path)
        det = detectors_builtin.EIP7702PluginDetector()
        opts = ScanOptions(use_slither=False, use_ast=False)
        result = det._timed_scan(ctx, opts)
        assert result.files_scanned >= 1
        assert len(result.findings) >= 1
        assert any("7702" in f.rule_id or "7702" in f.title.lower()
                   for f in result.findings)
        eip = next(f for f in result.findings if f.rule_id.startswith("AA7702"))
        assert "proof_recipe" in eip.metadata
        assert "semantic_context" in eip.metadata
        assert eip.metadata["proof_recipe"]["status"] == "needs_dynamic_confirmation"
        assert any("proof_adapters" in f.metadata for f in result.findings if f.rule_id.startswith("AA7702"))

    def test_bridge_zk_clean(self, tmp_sol_project):
        import detectors_builtin
        ctx = discover_project(tmp_sol_project)
        det = detectors_builtin.BridgeZKDetector()
        opts = ScanOptions(use_slither=False, use_ast=False)
        result = det._timed_scan(ctx, opts)
        assert result.files_scanned == 2
        assert len(result.findings) == 0  # no bridge/ZK patterns



# ── Discover + applicable tests ────────────────────────────────────────────

class TestDiscoverApplicable:
    def test_solidity_project(self, tmp_sol_project):
        import detectors_builtin, eip7702_validation
        ctx = discover_project(tmp_sol_project)
        applicable = discover_applicable(ctx)
        names = [d.name for d in applicable]
        assert "solidity" in names
        assert "eip7702" in names
        assert "eip7702_validation" in names
        assert "noir" not in names
