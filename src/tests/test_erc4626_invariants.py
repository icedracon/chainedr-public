"""
chainedr/tests/test_erc4626_invariants.py — Session 3 deterministic tests (RULE-03)

Acceptance criteria:
  PASS: rounding_model PRACTICAL → 0 FP on references
  PASS: rounding_model STRICT → may have FP (document them)
  PASS: donation_attack template → profitable on unguarded impl
  FAIL: any invariant fires on OZ+Solmate without PRACTICAL mode
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INVARIANTS_PATH = PROJECT_ROOT / "invariants" / "erc4626.json"
FIRST_DEP = PROJECT_ROOT / "templates" / "erc4626_first_depositor.sol"
DONATION = PROJECT_ROOT / "templates" / "erc4626_donation_attack.sol"
SHARE_MANIP = PROJECT_ROOT / "templates" / "erc4626_share_price_manip.sol"


class TestERC4626InvariantsJSON:
    @pytest.fixture(autouse=True)
    def load(self):
        with open(INVARIANTS_PATH, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_eip_4626(self):
        assert self.data["eip"] == "EIP-4626"

    def test_five_invariants(self):
        assert len(self.data["invariants"]) == 5

    def test_ids_unique(self):
        ids = [i["id"] for i in self.data["invariants"]]
        assert len(ids) == len(set(ids))

    def test_required_fields(self):
        for inv in self.data["invariants"]:
            assert "id" in inv and "eip_ref" in inv and "severity" in inv

    def test_rounding_model_practical(self):
        assert self.data["rounding_model"] == "PRACTICAL"

    def test_first_depositor_invariant(self):
        inv03 = next(i for i in self.data["invariants"] if i["id"] == "INV-4626-03")
        assert inv03["severity"] == "CRITICAL"


class TestRoundingModel:
    def test_import(self):
        from chainedr.compiler.rounding_model import RoundingMode, check_rounding
        assert RoundingMode.PRACTICAL.value == "PRACTICAL"

    def test_practical_1wei_pass(self):
        from chainedr.compiler.rounding_model import check_rounding
        result = check_rounding("deposit", 1000, 999, "EIP-4626")
        assert result["pass"] is True, "±1 wei should pass in PRACTICAL"

    def test_practical_2wei_fail(self):
        from chainedr.compiler.rounding_model import check_rounding
        result = check_rounding("deposit", 1000, 998, "EIP-4626")
        assert result["pass"] is False, "±2 wei should fail in PRACTICAL"

    def test_strict_1wei_fail(self):
        from chainedr.compiler.rounding_model import RoundingMode, check_rounding
        result = check_rounding("deposit", 1000, 999, "EIP-4626", RoundingMode.STRICT)
        assert result["pass"] is False, "±1 wei must fail in STRICT"

    def test_strict_exact_pass(self):
        from chainedr.compiler.rounding_model import RoundingMode, check_rounding
        result = check_rounding("deposit", 1000, 1000, "EIP-4626", RoundingMode.STRICT)
        assert result["pass"] is True

    def test_erc20_no_rounding(self):
        from chainedr.compiler.rounding_model import check_rounding
        result = check_rounding("default", 1000, 999, "EIP-20")
        assert result["pass"] is False, "ERC20 has no rounding tolerance"

    def test_erc20_exact_pass(self):
        from chainedr.compiler.rounding_model import check_rounding
        result = check_rounding("default", 1000, 1000, "EIP-20")
        assert result["pass"] is True

    def test_all_4626_operations_covered(self):
        from chainedr.compiler.rounding_model import ERC4626_PRACTICAL
        expected_ops = {"convertToShares", "convertToAssets", "deposit", "mint", "withdraw", "redeem"}
        assert set(ERC4626_PRACTICAL.keys()) == expected_ops

    def test_practical_tolerance_is_1wei(self):
        """CRITIC: tolerance must be ±1 wei. Larger = must explain."""
        from chainedr.compiler.rounding_model import ERC4626_PRACTICAL
        for op, tol in ERC4626_PRACTICAL.items():
            assert tol.wei_tolerance == 1, f"{op}: tolerance {tol.wei_tolerance} != 1 wei"


class TestTemplates:
    @pytest.mark.parametrize("path", [FIRST_DEP, DONATION, SHARE_MANIP])
    def test_exists(self, path):
        assert path.exists(), f"Missing: {path}"

    @pytest.mark.parametrize("path", [FIRST_DEP, DONATION, SHARE_MANIP])
    def test_no_imports(self, path):
        content = path.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.strip().startswith("import"):
                pytest.fail(f"External import in {path.name}: {line.strip()}")

    def test_first_depositor_has_unguarded_vault(self):
        content = FIRST_DEP.read_text(encoding="utf-8")
        assert "UnguardedVault" in content

    def test_donation_checks_totalassets(self):
        content = DONATION.read_text(encoding="utf-8")
        assert "totalAssets" in content

    def test_share_manip_has_practical_and_strict(self):
        content = SHARE_MANIP.read_text(encoding="utf-8")
        assert "practical" in content.lower()
        assert "strict" in content.lower()

    @pytest.mark.skipif(
        subprocess.run(["solc", "--version"], capture_output=True).returncode != 0,
        reason="solc not available",
    )
    @pytest.mark.parametrize("path", [FIRST_DEP, DONATION, SHARE_MANIP])
    def test_compiles(self, path):
        result = subprocess.run(["solc", "--bin", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{path.name} compile failed:\n{result.stderr}"
