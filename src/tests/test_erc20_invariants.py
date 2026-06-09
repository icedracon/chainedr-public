"""
chainedr/tests/test_erc20_invariants.py — Deterministic test on known data (RULE-03)

Acceptance criteria from Session 1:
  PASS: echidna on OZ ref → 0 invariant violations, 0 FP
  PASS: approve_race template → NOT profitable on OZ ref
  PASS: approve_race template → profitable on deliberately broken impl
  FAIL: any invariant fires on OZ ref without rounding model

This test validates:
  1. invariants/erc20.json loads correctly with all 5 invariants
  2. compiler/codegen.py generates valid Solidity from invariants
  3. Selector registry matches ERC20 ABI
  4. classifier detects ERC20 from ABI selectors
  5. Generated Solidity compiles (if solc available)

Run: python -m pytest chainedr/tests/test_erc20_invariants.py -v
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

# Paths relative to project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INVARIANTS_PATH = PROJECT_ROOT / "invariants" / "erc20.json"
SELECTOR_REGISTRY = PROJECT_ROOT / "selector_registry.json"
OZ_REF = PROJECT_ROOT / "references" / "erc20" / "oz_erc20_v5.sol"
SOLMATE_REF = PROJECT_ROOT / "references" / "erc20" / "solmate_erc20.sol"
APPROVE_RACE = PROJECT_ROOT / "templates" / "erc20_approve_race.sol"


# ============================================================================
# Test 1: Invariants JSON structure (RULE-08)
# ============================================================================

class TestInvariantsJSON:
    """Validate erc20.json schema and content."""

    @pytest.fixture(autouse=True)
    def load_invariants(self) -> None:
        assert INVARIANTS_PATH.exists(), f"Missing: {INVARIANTS_PATH}"
        with open(INVARIANTS_PATH, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_has_eip_fields(self) -> None:
        assert self.data["eip"] == "EIP-20"
        assert "eip_version" in self.data
        assert "rounding_model" in self.data

    def test_five_invariants(self) -> None:
        """Session 1 requires exactly 5 ERC-20 invariants."""
        assert len(self.data["invariants"]) == 5

    def test_invariant_ids_unique(self) -> None:
        ids = [inv["id"] for inv in self.data["invariants"]]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_each_invariant_has_required_fields(self) -> None:
        """RULE-08: Every invariant has id, eip_ref, severity."""
        required = {"id", "eip_ref", "severity"}
        for inv in self.data["invariants"]:
            missing = required - set(inv.keys())
            assert not missing, f"{inv['id']} missing fields: {missing}"

    def test_severity_values(self) -> None:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for inv in self.data["invariants"]:
            assert inv["severity"] in valid, (
                f"{inv['id']}: invalid severity '{inv['severity']}'"
            )

    def test_expected_invariant_ids(self) -> None:
        ids = {inv["id"] for inv in self.data["invariants"]}
        expected = {
            "INV-ERC20-01",  # supply conservation
            "INV-ERC20-02",  # transfer conservation
            "INV-ERC20-03",  # allowance accounting
            "INV-ERC20-04",  # approve race
            "INV-ERC20-05",  # zero transfer
        }
        assert ids == expected

    def test_approve_race_is_stateful(self) -> None:
        """CRITIC CHECK: INV-ERC20-04 must be STATEFUL_SEQUENCE, not single-tx."""
        inv04 = next(
            inv for inv in self.data["invariants"] if inv["id"] == "INV-ERC20-04"
        )
        assert inv04["type"] == "STATEFUL_SEQUENCE", (
            "INV-ERC20-04 MUST be STATEFUL_SEQUENCE. Single-tx is WRONG."
        )

    def test_supply_conservation_requires_ghost(self) -> None:
        """sum(balances)==totalSupply needs ghost variable tracking."""
        inv01 = next(
            inv for inv in self.data["invariants"] if inv["id"] == "INV-ERC20-01"
        )
        assert inv01["requires_ghost"] is True
        assert inv01.get("ghost_spec") is not None
        assert "variable" in inv01["ghost_spec"]

    def test_no_permit_invariants(self) -> None:
        """Session 1 scope: EIP-20 only. No EIP-2612 permit."""
        for inv in self.data["invariants"]:
            assert "permit" not in inv["name"].lower(), (
                f"{inv['id']} includes permit — out of scope for Session 1"
            )
            assert "2612" not in inv.get("eip_ref", ""), (
                f"{inv['id']} references EIP-2612 — out of scope"
            )

    def test_rounding_model_none_for_erc20(self) -> None:
        """ERC-20 has no rounding — all ops are exact integer."""
        assert self.data["rounding_model"] == "NONE"


# ============================================================================
# Test 2: Selector Registry
# ============================================================================

class TestSelectorRegistry:
    """Validate selector_registry.json for ERC20."""

    @pytest.fixture(autouse=True)
    def load_registry(self) -> None:
        assert SELECTOR_REGISTRY.exists()
        with open(SELECTOR_REGISTRY, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_has_erc20(self) -> None:
        assert "ERC20" in self.data["standards"]

    def test_six_required_selectors(self) -> None:
        erc20 = self.data["standards"]["ERC20"]
        required = erc20["required_selectors"]
        assert len(required) == 6
        # Verify known selectors
        assert "0x18160ddd" in required  # totalSupply
        assert "0x70a08231" in required  # balanceOf
        assert "0xa9059cbb" in required  # transfer
        assert "0x23b872dd" in required  # transferFrom
        assert "0x095ea7b3" in required  # approve
        assert "0xdd62ed3e" in required  # allowance

    def test_transfer_event_topic(self) -> None:
        erc20 = self.data["standards"]["ERC20"]
        events = erc20["events"]
        transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        assert transfer_topic in events
        assert events[transfer_topic]["name"] == "Transfer"

    def test_version_pinned(self) -> None:
        """RULE-05: version must be pinned."""
        assert "version" in self.data
        assert self.data["version"] != "latest"


# ============================================================================
# Test 3: Codegen produces valid output
# ============================================================================

class TestCodegen:
    """Validate that codegen produces Solidity from invariants JSON."""

    def test_codegen_imports(self) -> None:
        """codegen module must be importable."""
        from chainedr.compiler.codegen import InvariantSet, generate_echidna_harness
        assert callable(generate_echidna_harness)

    def test_codegen_loads_invariants(self) -> None:
        from chainedr.compiler.codegen import InvariantSet
        inv_set = InvariantSet.from_file(INVARIANTS_PATH)
        assert inv_set.eip == "EIP-20"
        assert len(inv_set.invariants) == 5

    def test_codegen_generates_solidity(self) -> None:
        from chainedr.compiler.codegen import InvariantSet, generate_echidna_harness
        inv_set = InvariantSet.from_file(INVARIANTS_PATH)
        source = generate_echidna_harness(inv_set)

        # Must contain Solidity pragma
        assert "pragma solidity" in source

        # Must contain echidna_ properties for implemented invariants
        assert "echidna_supply_conservation" in source
        assert "echidna_transfer_conservation" in source
        assert "echidna_allowance_accounting" in source
        assert "echidna_zero_transfer_must_succeed" in source

        # INV-ERC20-04 is in the dedicated template, should be noted
        assert "approve_race" in source.lower()

    def test_codegen_no_text_output(self) -> None:
        """CRITIC-04: codegen produces Solidity code, not text explanations."""
        from chainedr.compiler.codegen import InvariantSet, generate_echidna_harness
        inv_set = InvariantSet.from_file(INVARIANTS_PATH)
        source = generate_echidna_harness(inv_set)

        # Should not contain markdown or prose
        assert "# " not in source or source.index("# ") > source.index("//")
        assert "## " not in source


# ============================================================================
# Test 4: Reference files exist and compile
# ============================================================================

class TestReferences:
    """Validate reference implementations exist and are version-pinned."""

    def test_oz_ref_exists(self) -> None:
        assert OZ_REF.exists(), f"Missing OZ reference: {OZ_REF}"

    def test_solmate_ref_exists(self) -> None:
        assert SOLMATE_REF.exists(), f"Missing Solmate reference: {SOLMATE_REF}"

    def test_oz_ref_version_pinned(self) -> None:
        """RULE-05: no floating 'latest'."""
        content = OZ_REF.read_text(encoding="utf-8")
        assert "v5.0.2" in content, "OZ reference must be version-pinned to v5.0.2"
        assert "latest" not in content.lower().split("pragma")[0]

    def test_solmate_ref_version_pinned(self) -> None:
        """RULE-05: pinned to specific commit."""
        content = SOLMATE_REF.read_text(encoding="utf-8")
        assert "c892309" in content, "Solmate reference must be commit-pinned"

    def test_oz_ref_no_imports(self) -> None:
        """RULE-09: self-contained, no external deps."""
        content = OZ_REF.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("import"):
                # Allow only relative imports within the same file (none expected)
                pytest.fail(f"External import found: {stripped}")

    def test_solmate_ref_no_imports(self) -> None:
        """RULE-09: self-contained."""
        content = SOLMATE_REF.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("import"):
                pytest.fail(f"External import found: {stripped}")

    def test_approve_race_template_exists(self) -> None:
        assert APPROVE_RACE.exists()

    def test_approve_race_no_imports(self) -> None:
        """RULE-09: attack templates must be self-contained."""
        content = APPROVE_RACE.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("import"):
                pytest.fail(f"External import in attack template: {stripped}")

    def test_approve_race_has_broken_impl(self) -> None:
        """Template must include a deliberately broken ERC20 for validation."""
        content = APPROVE_RACE.read_text(encoding="utf-8")
        assert "BrokenERC20" in content
        assert "BUG" in content or "MISSING" in content

    @pytest.mark.skipif(
        subprocess.run(
            ["solc", "--version"], capture_output=True
        ).returncode != 0,
        reason="solc not available",
    )
    def test_oz_ref_compiles(self) -> None:
        """Compilation check (requires solc 0.8.20+)."""
        result = subprocess.run(
            ["solc", "--bin", str(OZ_REF)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"Compilation failed:\n{result.stderr}"


# ============================================================================
# Test 5: ABI Classifier
# ============================================================================

class TestClassifier:
    """Validate ABI-based protocol classifier for ERC20."""

    def test_classify_erc20_abi(self) -> None:
        """Classifier must detect ERC20 from ABI selectors."""
        from chainedr.classifier.abi_fingerprint import classify_abi

        # Standard ERC20 ABI selectors
        erc20_selectors = [
            "0x18160ddd", "0x70a08231", "0xa9059cbb",
            "0x23b872dd", "0x095ea7b3", "0xdd62ed3e",
        ]
        result = classify_abi(erc20_selectors)
        assert result["protocol"] == "ERC20"
        assert result["confidence"] >= 0.9

    def test_classify_non_erc20(self) -> None:
        """Non-ERC20 ABI must not classify as ERC20."""
        from chainedr.classifier.abi_fingerprint import classify_abi

        random_selectors = ["0xdeadbeef", "0xcafebabe"]
        result = classify_abi(random_selectors)
        assert result["protocol"] != "ERC20" or result["confidence"] < 0.5

    def test_classify_partial_erc20(self) -> None:
        """Partial ERC20 (missing functions) should lower confidence."""
        from chainedr.classifier.abi_fingerprint import classify_abi

        partial = ["0x18160ddd", "0x70a08231", "0xa9059cbb"]  # 3 of 6
        result = classify_abi(partial)
        assert result["confidence"] < 0.9


# ============================================================================
# CRITIC-06 summary: After running tests, report pass/fail and FP count.
#
# Expected results on clean run:
#   - All TestInvariantsJSON: PASS
#   - All TestSelectorRegistry: PASS
#   - All TestCodegen: PASS
#   - All TestReferences: PASS (compilation skipped if no solc)
#   - All TestClassifier: PASS
#   - FP count: 0 (no false positives in invariants on reference impls)
# ============================================================================
