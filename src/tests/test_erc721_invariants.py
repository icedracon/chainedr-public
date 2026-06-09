"""
chainedr/tests/test_erc721_invariants.py — Session 2 deterministic tests (RULE-03)

Acceptance criteria:
  PASS: MaliciousReceiver on OZ ERC721 → NOT profitable (OZ is safe)
  PASS: MaliciousReceiver on broken impl → profitable
  PASS: selector registry detects both safeTransferFrom selectors
  FAIL: onERC721Received callback not actually called in template
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INVARIANTS_PATH = PROJECT_ROOT / "invariants" / "erc721.json"
SELECTOR_REGISTRY = PROJECT_ROOT / "selector_registry.json"
REENTRANT_TEMPLATE = PROJECT_ROOT / "templates" / "erc721_receiver_reentrant.sol"


class TestERC721InvariantsJSON:
    @pytest.fixture(autouse=True)
    def load(self) -> None:
        assert INVARIANTS_PATH.exists()
        with open(INVARIANTS_PATH, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_eip_721(self) -> None:
        assert self.data["eip"] == "EIP-721"

    def test_five_invariants(self) -> None:
        assert len(self.data["invariants"]) == 5

    def test_ids_unique(self) -> None:
        ids = [inv["id"] for inv in self.data["invariants"]]
        assert len(ids) == len(set(ids))

    def test_required_fields(self) -> None:
        for inv in self.data["invariants"]:
            assert "id" in inv
            assert "eip_ref" in inv
            assert "severity" in inv

    def test_expected_ids(self) -> None:
        ids = {inv["id"] for inv in self.data["invariants"]}
        expected = {
            "INV-721-01", "INV-721-02", "INV-721-03",
            "INV-721-04", "INV-721-05",
        }
        assert ids == expected

    def test_receiver_check_invariant(self) -> None:
        """INV-721-04 must check onERC721Received return value, not just revert."""
        inv04 = next(i for i in self.data["invariants"] if i["id"] == "INV-721-04")
        assert "0x150b7a02" in inv04["check_expr"], (
            "CRITIC: Must check return value == 0x150b7a02, not just revert-or-not"
        )

    def test_rounding_none(self) -> None:
        assert self.data["rounding_model"] == "NONE"


class TestSelectorRegistryERC721:
    @pytest.fixture(autouse=True)
    def load(self) -> None:
        with open(SELECTOR_REGISTRY, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_has_erc721(self) -> None:
        assert "ERC721" in self.data["standards"]

    def test_both_safe_transfer_selectors(self) -> None:
        """CRITIC: safeTransferFrom has TWO selectors. Missing one = silent misclassification."""
        erc721 = self.data["standards"]["ERC721"]
        selectors = erc721["selectors"]
        # 3-arg: safeTransferFrom(address,address,uint256) → 0x42842e0e
        assert "0x42842e0e" in selectors, "Missing 3-arg safeTransferFrom selector"
        # 4-arg: safeTransferFrom(address,address,uint256,bytes) → 0xb88d4fde
        assert "0xb88d4fde" in selectors, "Missing 4-arg safeTransferFrom selector"

    def test_both_in_required(self) -> None:
        required = self.data["standards"]["ERC721"]["required_selectors"]
        assert "0x42842e0e" in required
        assert "0xb88d4fde" in required

    def test_receiver_selector(self) -> None:
        """onERC721Received selector must be registered."""
        erc721 = self.data["standards"]["ERC721"]
        assert "receiver_interface" in erc721
        assert "0x150b7a02" in erc721["receiver_interface"]

    def test_nine_required_selectors(self) -> None:
        required = self.data["standards"]["ERC721"]["required_selectors"]
        assert len(required) == 9

    def test_classifier_detects_erc721(self) -> None:
        from chainedr.classifier.abi_fingerprint import classify_abi
        erc721_sels = [
            "0x70a08231", "0x6352211e", "0x42842e0e", "0xb88d4fde",
            "0x23b872dd", "0x095ea7b3", "0x081812fc", "0xa22cb465", "0xe985e9c5",
        ]
        result = classify_abi(erc721_sels)
        assert result["protocol"] == "ERC721"
        assert result["confidence"] >= 0.9


class TestReentrancyTemplate:
    def test_template_exists(self) -> None:
        assert REENTRANT_TEMPLATE.exists()

    def test_no_imports(self) -> None:
        """RULE-09: self-contained."""
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.strip().startswith("import"):
                pytest.fail(f"External import: {line.strip()}")

    def test_has_malicious_receiver(self) -> None:
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        assert "MaliciousReceiver" in content

    def test_has_broken_impl(self) -> None:
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        assert "BrokenERC721" in content

    def test_callback_returns_correct_selector(self) -> None:
        """CRITIC: onERC721Received must return 0x150b7a02, not just succeed."""
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        assert "0x150b7a02" in content or "onERC721Received.selector" in content

    def test_wrong_selector_receiver(self) -> None:
        """Template must include a WrongSelectorReceiver for INV-721-05."""
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        assert "WrongSelectorReceiver" in content
        assert "0xdeadbeef" in content

    def test_has_both_safe_transfer_variants(self) -> None:
        """Both safeTransferFrom overloads must be in the interface."""
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        assert "safeTransferFrom(address from, address to, uint256 tokenId)" in content
        assert "safeTransferFrom(address from, address to, uint256 tokenId, bytes" in content

    def test_cei_violation_documented(self) -> None:
        """BrokenERC721 must have callback BEFORE state update."""
        content = REENTRANT_TEMPLATE.read_text(encoding="utf-8")
        assert "BEFORE" in content.upper() or "before state" in content.lower()

    @pytest.mark.skipif(
        subprocess.run(["solc", "--version"], capture_output=True).returncode != 0,
        reason="solc not available",
    )
    def test_template_compiles(self) -> None:
        result = subprocess.run(
            ["solc", "--bin", str(REENTRANT_TEMPLATE)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"Compile failed:\n{result.stderr}"


class TestERC20StillWorks:
    """Regression: Session 1 ERC20 tests must still pass."""

    def test_erc20_invariants_exist(self) -> None:
        assert (PROJECT_ROOT / "invariants" / "erc20.json").exists()

    def test_classifier_erc20(self) -> None:
        from chainedr.classifier.abi_fingerprint import classify_abi
        result = classify_abi(["0x18160ddd", "0x70a08231", "0xa9059cbb",
                               "0x23b872dd", "0x095ea7b3", "0xdd62ed3e"])
        assert result["protocol"] == "ERC20"
        assert result["confidence"] >= 0.9

    def test_erc20_not_misclassified_as_721(self) -> None:
        """ERC20 and ERC721 share some selectors. Must not confuse them."""
        from chainedr.classifier.abi_fingerprint import classify_abi
        # Pure ERC20 selectors (no ownerOf, no getApproved)
        result = classify_abi(["0x18160ddd", "0xa9059cbb", "0xdd62ed3e"])
        assert result["protocol"] != "ERC721"
