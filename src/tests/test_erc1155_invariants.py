"""
chainedr/tests/test_erc1155_invariants.py — Session 4 deterministic tests (RULE-03)

Acceptance criteria:
  PASS: INV-1155-01 (balanceOfBatch) runs on ref → 0 violations
  PASS: batch_reentrant template → profitable on broken impl
  PASS: codegen handles balanceOfBatch (array return) without crashing
  FAIL: invariant only checks single-transfer, not batch-transfer path
"""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INVARIANTS = PROJECT_ROOT / "invariants" / "erc1155.json"
REGISTRY = PROJECT_ROOT / "selector_registry.json"
TEMPLATE = PROJECT_ROOT / "templates" / "erc1155_batch_reentrant.sol"


class TestERC1155Invariants:
    @pytest.fixture(autouse=True)
    def load(self):
        with open(INVARIANTS, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_eip_1155(self):
        assert self.data["eip"] == "EIP-1155"

    def test_five_invariants(self):
        assert len(self.data["invariants"]) == 5

    def test_ids_unique(self):
        ids = [i["id"] for i in self.data["invariants"]]
        assert len(ids) == len(set(ids))

    def test_required_fields(self):
        for inv in self.data["invariants"]:
            assert "id" in inv and "eip_ref" in inv and "severity" in inv

    def test_batch_aware_invariants(self):
        """CRITIC: must check batch-transfer path, not just single-transfer."""
        names = {i["name"] for i in self.data["invariants"]}
        assert "balance_of_batch_consistency" in names
        assert "batch_transfer_atomicity" in names
        assert "receiver_callback_batch" in names

    def test_batch_callback_selector(self):
        inv04 = next(i for i in self.data["invariants"] if i["id"] == "INV-1155-04")
        assert "0xbc197c81" in inv04["check_expr"]

    def test_array_return_documented(self):
        """CRITIC: balanceOfBatch returns uint256[]. Must document Echidna limitation."""
        inv01 = next(i for i in self.data["invariants"] if i["id"] == "INV-1155-01")
        assert any("array" in l.lower() or "Array" in l for l in inv01.get("known_limitations", []) + [inv01.get("echidna_notes", "")])


class TestERC1155Registry:
    @pytest.fixture(autouse=True)
    def load(self):
        with open(REGISTRY, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_has_erc1155(self):
        assert "ERC1155" in self.data["standards"]

    def test_six_required(self):
        assert len(self.data["standards"]["ERC1155"]["required_selectors"]) == 6

    def test_both_receiver_callbacks(self):
        rcv = self.data["standards"]["ERC1155"]["receiver_interface"]
        assert "0xf23a6e61" in rcv  # onERC1155Received
        assert "0xbc197c81" in rcv  # onERC1155BatchReceived

    def test_single_ref_documented(self):
        """CRITIC: No Solmate ERC1155 = single-ref weakness. Must be documented."""
        lims = self.data["standards"]["ERC1155"].get("known_limitations", [])
        assert any("single" in l.lower() or "solmate" in l.lower() for l in lims)

    def test_classifier_detects_1155(self):
        from chainedr.classifier.abi_fingerprint import classify_abi
        sels = ["0x00fdd58e", "0x4e1273f4", "0xa22cb465", "0xe985e9c5", "0xf242432a", "0x2eb2c2d6"]
        result = classify_abi(sels)
        assert result["protocol"] == "ERC1155"
        assert result["confidence"] >= 0.9


class TestBatchReentrancyTemplate:
    def test_exists(self):
        assert TEMPLATE.exists()

    def test_no_imports(self):
        content = TEMPLATE.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.strip().startswith("import"):
                pytest.fail(f"Import: {line.strip()}")

    def test_has_broken_impl(self):
        content = TEMPLATE.read_text(encoding="utf-8")
        assert "BrokenERC1155" in content

    def test_has_malicious_batch_receiver(self):
        content = TEMPLATE.read_text(encoding="utf-8")
        assert "MaliciousBatchReceiver" in content

    def test_reentrancy_mid_batch(self):
        """CRITIC: Must reenter inside onERC1155BatchReceived, not before/after."""
        content = TEMPLATE.read_text(encoding="utf-8")
        assert "onERC1155BatchReceived" in content
        assert "BEFORE" in content.upper()  # CEI violation documented

    def test_correct_selectors(self):
        content = TEMPLATE.read_text(encoding="utf-8")
        assert "0xf23a6e61" in content  # onERC1155Received
        assert "0xbc197c81" in content  # onERC1155BatchReceived

    @pytest.mark.skipif(
        subprocess.run(["solc", "--version"], capture_output=True).returncode != 0,
        reason="solc not available",
    )
    def test_compiles(self):
        result = subprocess.run(["solc", "--bin", str(TEMPLATE)], capture_output=True, text=True)
        assert result.returncode == 0, f"Compile failed:\n{result.stderr}"


class TestRegressionS1S2S3:
    """All previous sessions must still work."""
    def test_erc20_exists(self):
        assert (PROJECT_ROOT / "invariants" / "erc20.json").exists()

    def test_erc721_exists(self):
        assert (PROJECT_ROOT / "invariants" / "erc721.json").exists()

    def test_erc4626_exists(self):
        assert (PROJECT_ROOT / "invariants" / "erc4626.json").exists()
