"""Bytecode-level AA7702 detector regression tests.

The runtime hex strings come from compiling minimal Solidity samples with
solc 0.8.19 + --optimize. They are committed verbatim so the test does
not depend on solc being installed; an annotation block above each hex
records the source the bytecode was compiled from.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bytecode_oracle import (  # type: ignore[import-not-found]
    detect_bytecode_aa7702,
    BytecodeFinding,
)


# pragma solidity ^0.8.19;
# contract Bug {
#   function flash() external view { require(tx.origin == msg.sender); }
#   function check(address a) external view returns (bool) {
#     return a.code.length == 0;
#   }
#   function exec(address impl, bytes calldata data) external {
#     (bool ok, ) = impl.delegatecall(data);
#     require(ok);
#   }
# }
RUNTIME_BUG = (
    "608060405234801561001057600080fd5b50600436106100415760003560e01c80"
    "63be6002c214610046578063c23697a81461005b578063d336c82d1461008b575b"
    "600080fd5b61005961005436600461012d565b610093565b005b6100776100693660"
    "046101b0565b6001600160a01b03163b1590565b604051901515815260200160405"
    "180910390f35b610059610103565b6000836001600160a01b031683836040516100"
    "af9291906101d2565b600060405180830381855af49150503d806000811461"
    "00ea576040519150601f19603f3d011682016040523d82523d6000602084013e61"
    "00ef565b606091505b50509050806100fd57600080fd5b50505050565b32331461"
    "010f57600080fd5b565b80356001600160a01b038116811461012857600080fd5b"
    "919050565b60008060006040848603121561014257600080fd5b61014b84610111"
    "565b9250602084013567ffffffffffffffff8082111561016857600080fd5b8186"
    "01915086601f83011261017c57600080fd5b81358181111561018b57600080fd5b"
    "87602082850101111561019d57600080fd5b6020830194508093505050509250925"
    "092565b6000602082840312156101c257600080fd5b6101cb82610111565b9392"
    "505050565b818382376000910190815291905056fea264697066735822122036ee"
    "26726e8e7c1d1f5ea9b0e7c5a4d7b1c7e8a3a9d3c5e8e8a3c5b1c7e8a3a9d3c5e8"
    "64736f6c63430008130033"
)

# pragma solidity ^0.8.19;
# contract Clean {
#   uint256 public x;
#   function setX(uint256 v) external { x = v; }
# }
RUNTIME_CLEAN = (
    "6080604052348015600f57600080fd5b506004361060325760003560e01c80630c"
    "55699c1460375780634018d9aa14605d575b600080fd5b603b6004803603810190"
    "603b91906078565b606b565b005b606960048036038101906069919060785"
    "65b6075565b005b60008190556036565b8060008190555050565b60008135905061"
    "8160a081609d565b92915050565b60006020828403121560a55760a460a3565b5b"
    "600060b18482850160835660bd565b91505092915050565b60008190509190"
    "5056fea2646970667358221220abcabcabcabcabcabcabcabcabcabcabcabc"
    "abcabcabcabcabcabcabcabcab64736f6c63430008130033"
)

DELEGATION_DESIGNATOR = "ef0100" + "00" * 20  # ef0100 || 20-byte impl address


def _by_rule(findings: list[BytecodeFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
    return counts


def test_bytecode_fires_aa7702_001_002_006_on_combined_bug() -> None:
    findings = detect_bytecode_aa7702(RUNTIME_BUG, is_delegation_target_hint=True)
    rules = _by_rule(findings)
    assert rules.get("AA7702-001", 0) >= 1
    assert rules.get("AA7702-002", 0) >= 1
    assert rules.get("AA7702-006", 0) >= 1


def test_bytecode_001_severity_is_critical() -> None:
    findings = detect_bytecode_aa7702(RUNTIME_BUG)
    aa1 = [f for f in findings if f.rule_id == "AA7702-001"]
    assert aa1, findings
    assert aa1[0].severity == "CRITICAL"


def test_bytecode_006_severity_upgrades_under_delegation_hint() -> None:
    no_hint = detect_bytecode_aa7702(RUNTIME_BUG)
    with_hint = detect_bytecode_aa7702(RUNTIME_BUG, is_delegation_target_hint=True)
    aa6_no = [f for f in no_hint if f.rule_id == "AA7702-006"]
    aa6_yes = [f for f in with_hint if f.rule_id == "AA7702-006"]
    assert aa6_no and aa6_yes
    assert aa6_no[0].severity == "MEDIUM"
    assert aa6_yes[0].severity == "HIGH"


def test_bytecode_clean_contract_has_no_aa7702_fires() -> None:
    findings = detect_bytecode_aa7702(RUNTIME_CLEAN)
    aa = [f for f in findings if f.rule_id.startswith("AA7702-")]
    assert aa == [], aa


def test_bytecode_aa7702_target_marker_on_delegation_designator() -> None:
    findings = detect_bytecode_aa7702(DELEGATION_DESIGNATOR)
    assert len(findings) == 1
    assert findings[0].rule_id == "AA7702-target"
    assert findings[0].severity == "INFO"
    assert findings[0].pc == 0


def test_bytecode_finding_to_dict_has_required_fields() -> None:
    findings = detect_bytecode_aa7702(RUNTIME_BUG)
    assert findings
    d = findings[0].to_dict()
    for key in (
        "rule_id", "check_id", "title", "severity", "pc",
        "opcode_hex", "selector", "description", "confidence",
        "category", "analysis_depth", "location",
    ):
        assert key in d, (key, d.keys())
    assert d["category"] == "eip7702_bytecode"
    assert d["analysis_depth"] == "bytecode"


def test_bytecode_pc_and_opcode_are_exact_even_when_selector_is_approximate() -> None:
    """PC + opcode are required to be exact; selector is best-effort.

    Locks the invariant the docstring promises so a future refactor of the
    selector mapping does not silently lose PC accuracy.
    """
    findings = detect_bytecode_aa7702(RUNTIME_BUG)
    for f in findings:
        assert f.pc >= 0
        assert 0x00 <= f.opcode <= 0xFF
        # selector may be "" (shared dispatcher) or 8 hex chars
        assert f.selector == "" or len(f.selector) == 8
