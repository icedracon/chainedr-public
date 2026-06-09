"""Tests for EIP-7702 sandbox policy and pre-behavior trace metadata."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli import _write_json, _write_sarif
from detector_plugin import ScanOptions
from eip7702_detector import (
    EIP7702Detector,
    _strip_comments,
    detect_tx_origin_eoa_bypass,
)
from eip7702_sandbox import (
    SandboxPolicy,
    build_pre_behavior_trace,
)
from project_context import discover_project


EIP7702_IDENTITY_SAMPLE = """
pragma solidity ^0.8.0;

contract WalletGate {
    function execute(address target) external {
        require(tx.origin == msg.sender, "EOA only");
        (bool ok,) = target.call("");
        require(ok);
    }
}
"""


def test_direct_eip7702_findings_include_sandbox_trace():
    findings = detect_tx_origin_eoa_bypass(_strip_comments(EIP7702_IDENTITY_SAMPLE))

    assert findings
    finding = findings[0]
    assert finding.sandbox_policy.identity_boundary
    assert finding.sandbox_boundary == "identity_boundary"
    assert finding.sandbox_bypass_class == "identity_assumption_bypass"
    assert finding.pre_behavior_trace is not None
    assert finding.pre_behavior_trace.violated_boundary == "identity_boundary"
    assert finding.pre_behavior_trace.assumptions_detected
    assert finding.pre_behavior_trace.delegated_behavior_possible

    as_dict = finding.to_dict()
    assert as_dict["pre_behavior_trace"]["violated_boundary"] == "identity_boundary"
    assert as_dict["sandbox_policy"]["identity_boundary"] == SandboxPolicy().identity_boundary


def test_all_eip7702_rules_have_sandbox_templates():
    detector = EIP7702Detector()
    policy_fields = SandboxPolicy().to_dict()

    for idx in range(1, len(detector._ALL_CHECKS) + 1):
        check_id = f"AA7702-{idx:03d}"
        trace = build_pre_behavior_trace(
            check_id,
            title=f"{check_id} test",
            location="line 1",
            description="test evidence",
            confidence=0.77,
        )
        assert trace.violated_boundary in policy_fields
        assert trace.violated_sandbox_rule == policy_fields[trace.violated_boundary]
        assert trace.bypass_class
        assert trace.confidence == 0.77


def test_plugin_finding_exposes_pre_behavior_metadata(tmp_path):
    import detectors_builtin

    (tmp_path / "WalletGate.sol").write_text(EIP7702_IDENTITY_SAMPLE)
    ctx = discover_project(tmp_path)
    result = detectors_builtin.EIP7702PluginDetector()._timed_scan(
        ctx,
        ScanOptions(use_slither=False, use_ast=False),
    )

    aa7702_001 = [f for f in result.findings if f.rule_id == "AA7702-001"]
    assert aa7702_001
    finding = aa7702_001[0]
    assert finding.metadata["sandbox_boundary"] == "identity_boundary"
    assert finding.metadata["sandbox_bypass_class"] == "identity_assumption_bypass"
    assert finding.metadata["pre_behavior_trace"]["violated_boundary"] == "identity_boundary"

    as_dict = finding.to_dict()
    assert as_dict["metadata"]["pre_behavior_trace"]["assumptions_detected"]


def test_json_and_sarif_outputs_preserve_sandbox_metadata(tmp_path):
    import detectors_builtin

    (tmp_path / "WalletGate.sol").write_text(EIP7702_IDENTITY_SAMPLE)
    ctx = discover_project(tmp_path)
    result = detectors_builtin.EIP7702PluginDetector()._timed_scan(
        ctx,
        ScanOptions(use_slither=False, use_ast=False),
    )

    findings = [f for f in result.findings if f.rule_id == "AA7702-001"]
    assert findings

    json_path = tmp_path / "scan.json"
    sarif_path = tmp_path / "scan.sarif"
    _write_json(json_path, findings, ctx, elapsed=0.01)
    _write_sarif(sarif_path, findings)

    json_data = json.loads(json_path.read_text())
    metadata = json_data["findings"][0]["metadata"]
    assert metadata["pre_behavior_trace"]["violated_boundary"] == "identity_boundary"
    assert metadata["sandbox_policy"]["identity_boundary"]

    sarif_data = json.loads(sarif_path.read_text())
    sarif_metadata = sarif_data["runs"][0]["results"][0]["properties"]["metadata"]
    assert sarif_metadata["pre_behavior_trace"]["bypass_class"] == "identity_assumption_bypass"
