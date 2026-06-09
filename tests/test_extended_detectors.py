"""
Smoke tests for the extended detector modules (EIP-7702 ext, ERC-7821, MEV,
ERC-6900). Verifies each entry point fires on a positive sample and is clean on
a benign one — and that they're wired into the scan pipeline.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import eip7702_extensions as ext       # noqa: E402
import erc7821_checker as e7821        # noqa: E402
import mev_and_erc6900_checker as mev  # noqa: E402

BENIGN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Plain { uint256 public x; function setX(uint256 v) external { x = v; } }
"""

ERC7821 = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Batch { function execute(bytes32 mode, bytes calldata opData) external payable {} }
"""

SWAP = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Dex { function swap(uint256 amountIn, address tokenOut) external returns (uint256) { return amountIn; } }
"""


def test_erc7821_fires_on_mode_without_validation():
    ids = [f.check_id for f in e7821.check_erc7821(ERC7821)]
    assert any(i.startswith("ERC7821-") for i in ids), ids


def test_mev_fires_on_swap_without_slippage():
    ids = [f.check_id for f in mev.check_mev_protection(SWAP)]
    assert any(i.startswith("MEV-") for i in ids), ids


def test_mev_skips_swap_with_named_min_output_guard():
    source = """
pragma solidity ^0.8.17;
contract Swapper {
  function swap(address account, uint256 minEXA, uint256 keepETH) external payable {
    uint256 outEXA = getAmountOut();
    if (outEXA < minEXA) return;
    poolSwap(outEXA, account);
  }
  function getAmountOut() internal pure returns (uint256) { return 1; }
  function poolSwap(uint256, address) internal {}
}
"""
    assert [f.check_id for f in mev.check_mev_protection(source)] == []


def test_mev_skips_interface_swap_with_params_struct_slippage():
    source = """
pragma solidity ^0.8.25;
interface ISwapModule {
  struct Params {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    uint256 deadline;
  }
  function swap(Params calldata params, address router, bytes calldata data)
    external
    returns (bytes memory response);
}
"""
    assert [f.check_id for f in mev.check_mev_protection(source)] == []


def test_aggregator_rule_skips_chainlink_oracle_context():
    source = """
pragma solidity ^0.8.0;
interface AggregatorV3Interface {
  function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}
contract ChainlinkOracle {
  AggregatorV3Interface public immutable feed;
  constructor(AggregatorV3Interface feed_) { feed = feed_; }
}
"""
    assert [f.check_id for f in ext.detect_aggregator_signature_collision(source)] == []


def test_aggregator_rule_still_fires_on_erc4337_signature_aggregator():
    source = """
pragma solidity ^0.8.0;
struct PackedUserOperation { bytes signature; }
contract Agg {
  function aggregateSignatures(PackedUserOperation[] calldata ops) external view returns (bytes memory) {
    ops;
    return "";
  }
  function validateSignatures(PackedUserOperation[] calldata ops, bytes calldata signature) external view {
    ops; signature;
  }
}
"""
    assert [f.check_id for f in ext.detect_aggregator_signature_collision(source)] == ["AA7702-024"]


def test_extended_entry_points_return_lists_on_benign():
    # benign code: no crash, returns lists (may be empty)
    assert isinstance(ext.run_extended_checks(BENIGN), list)
    assert isinstance(e7821.check_erc7821(BENIGN), list)
    assert isinstance(mev.check_mev_protection(BENIGN), list)
    assert isinstance(mev.check_erc6900(BENIGN), list)


def test_extended_off_by_default_on_by_flag(tmp_path):
    """`chainedr scan` keeps extended detectors off unless --extended is passed.

    Exercises the wiring through the v3 CLI's project context + plugin registry
    rather than through the deleted legacy Hunter.
    """
    import types as _types, sys as _sys, io as _io, json as _json, argparse as _ap
    repo = Path(__file__).resolve().parent.parent
    _sys.path.insert(0, str(repo))
    mod = _types.ModuleType("chainedr")
    mod.__path__ = [str(repo / "src")]
    _sys.modules["chainedr"] = mod
    import chainedr.cli as cli  # type: ignore[import-not-found]

    (tmp_path / "Batch.sol").write_text(ERC7821)

    def _scan(extended_flag: bool) -> list:
        out_json = tmp_path / f"_scan_extended_{int(extended_flag)}.json"
        ns = _ap.Namespace(
            target=str(tmp_path),
            no_external=True,
            no_ast=False,
            deep=False,
            extended=extended_flag,
            mythril=False,
            external_timeout=30,
            ignore=[],
            min_severity="LOW",
            format="compact",
            sarif=None,
            json_out=str(out_json),
            fail_on=None,
            profile="default",
            output_dir=None,
            ai_triage=False,
            prove=False,
            prove_on_finding=[],
            prove_out=None,
        )
        saved = _sys.stdout, _sys.stderr
        _sys.stdout, _sys.stderr = _io.StringIO(), _io.StringIO()
        try:
            cli.cmd_scan(ns)
        finally:
            _sys.stdout, _sys.stderr = saved
        return _json.loads(out_json.read_text(encoding="utf-8")).get("findings", [])

    default_rules = {f.get("rule_id", "") for f in _scan(False)}
    extended_rules = {f.get("rule_id", "") for f in _scan(True)}

    assert not any(r.startswith("ERC7821-") for r in default_rules), default_rules
    assert any(r.startswith("ERC7821-") for r in extended_rules), extended_rules
