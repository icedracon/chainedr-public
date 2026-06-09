"""Tests for the opt-in `chainedr scan --confirm` path."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli import _write_json, build_parser
import confirmation
from confirmation import ConfirmationOptions, confirm_findings
from detector_plugin import Finding, Severity
from project_context import discover_project


def _aa7702_002_finding() -> Finding:
    return Finding(
        detector="eip7702",
        rule_id="AA7702-002",
        severity=Severity.HIGH,
        title="EIP-7702 breaks EOA detection via code.length",
        description="code.length is used as an EOA boundary",
        file_path="Gate.sol",
        category="eip7702",
        confidence=0.90,
    )


def test_scan_parser_accepts_confirm_flags():
    args = build_parser().parse_args([
        "scan",
        "contracts",
        "--deep",
        "--confirm",
        "--confirm-rpc-url",
        "http://localhost:8545",
        "--confirm-eoa",
        "0x00000000000000000000000000000000DeAd7702",
        "--confirm-implementation",
        "0x0000000000000000000000000000000000000001",
        "--confirm-fork-block",
        "123",
    ])

    assert args.command == "scan"
    assert args.deep is True
    assert args.confirm is True
    assert args.confirm_rpc_url == "http://localhost:8545"
    assert args.confirm_fork_block == 123


def test_ci_parser_accepts_positional_and_target_option():
    positional = build_parser().parse_args(["ci", "contracts", "--no-external"])
    target_opt = build_parser().parse_args(["ci", "--target", "contracts", "--no-external"])
    init = build_parser().parse_args(["ci", "init"])

    assert positional.command == "ci"
    assert positional.target == "contracts"
    assert positional.target_opt is None
    assert target_opt.target is None
    assert target_opt.target_opt == "contracts"
    assert init.target == "init"


def test_confirm_findings_skips_without_rpc_url():
    finding = _aa7702_002_finding()

    summary = confirm_findings([finding], ConfirmationOptions(enabled=True))

    assert summary.status == "skipped"
    assert summary.eligible == 1
    assert summary.skipped == 1
    dc = finding.metadata["dynamic_confirmation"]
    assert dc["status"] == "skipped"
    assert dc["proof_status"] == "STATIC_CANDIDATE"
    assert dc["rule_id"] == "AA7702-002"
    assert "RPC URL required" in dc["reason"]


def test_confirm_findings_attaches_proof_evidence(monkeypatch):
    finding = _aa7702_002_finding()
    finding.metadata["proof_recipe"] = {
        "check_id": "AA7702-002",
        "status": "needs_dynamic_confirmation",
        "proof_status": "CONFIRMABLE",
    }

    monkeypatch.setattr(confirmation.shutil, "which", lambda name: "solc")
    monkeypatch.setattr(
        confirmation,
        "_run_eip7702_code_presence_probe",
        lambda opts: {
            "finding": "AA7702-002",
            "dynamically_confirmed": True,
            "value_before_delegation": True,
            "value_after_delegation": False,
            "detail": "flip",
            "evidence": {
                "code_before": "0x",
                "code_after": "0xef01000000000000000000000000000000000000000001",
                "is_delegated_after": True,
            },
        },
    )

    summary = confirm_findings(
        [finding],
        ConfirmationOptions(enabled=True, rpc_url="http://localhost:8545"),
    )

    assert summary.status == "confirmed"
    dc = finding.metadata["dynamic_confirmation"]
    assert dc["proof_status"] == "CONFIRMED_IMPACT"
    assert dc["evidence"]["observed_behavior_flip"] is True
    assert dc["evidence"]["is_delegated_after"] is True
    assert finding.metadata["proof_recipe"]["proof_status"] == "CONFIRMED_IMPACT"


def test_confirm_metadata_is_preserved_in_json_summary(tmp_path):
    finding = _aa7702_002_finding()
    confirm_findings([finding], ConfirmationOptions(enabled=True))

    ctx = discover_project(tmp_path)
    out = tmp_path / "scan.json"
    _write_json(out, [finding], ctx, elapsed=0.01)

    data = json.loads(out.read_text())
    assert data["summary"]["dynamic_confirmation"]["skipped"] == 1
    assert data["findings"][0]["metadata"]["dynamic_confirmation"]["status"] == "skipped"
