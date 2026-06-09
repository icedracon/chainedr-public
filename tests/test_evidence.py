"""Evidence bundle and demo-pack regressions."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evidence import (  # noqa: E402
    render_evidence_bundle,
    run_friend_demo,
    run_reviewer_package,
    write_evidence_bundle,
)


def test_evidence_bundle_includes_review_context(tmp_path):
    source = tmp_path / "Target.sol"
    source.write_text(
        "\n".join(
            [
                "// SPDX-License-Identifier: MIT",
                "pragma solidity ^0.8.20;",
                "contract Target {",
                "    function enter() external {",
                "        require(tx.origin == msg.sender, 'human only');",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    report = {
        "summary": {
            "by_severity": {"HIGH": 1},
            "by_detector": {"eip7702": 1},
        },
        "findings": [
            {
                "detector": "eip7702",
                "rule_id": "AA7702-001",
                "severity": "HIGH",
                "title": "tx.origin EOA bypass",
                "description": "tx.origin == msg.sender is no longer an EOA proof after EIP-7702.",
                "file_path": str(source),
                "line": 5,
                "confidence": 0.9,
                "fix": "Use explicit authorization instead of tx.origin.",
            }
        ],
    }
    json_path = tmp_path / "scan.json"
    json_path.write_text(json.dumps(report), encoding="utf-8")

    output = tmp_path / "bundle.md"
    result = write_evidence_bundle(json_path, output, source_root=tmp_path)

    assert result["findings"] == 1
    rendered = output.read_text(encoding="utf-8")
    assert "AA7702-001" in rendered
    assert "REAL_CANDIDATE" in rendered
    assert "require(tx.origin == msg.sender" in rendered
    assert "Use explicit authorization" in rendered


def test_render_evidence_bundle_handles_empty_report(tmp_path):
    rendered = render_evidence_bundle({"findings": []}, tmp_path)

    assert "Total findings" in rendered
    assert "No findings were present" in rendered


def test_friend_demo_pack_generates_core_artifacts(tmp_path):
    result = run_friend_demo(tmp_path / "demo", include_benchmark=False)

    out = Path(result["output_dir"])
    assert result["vulnerable_findings"] >= 1
    assert result["fixed_findings"] == 0
    assert (out / "report.md").exists()
    assert (out / "vulnerable_txorigin.json").exists()
    assert (out / "fixed_txorigin.json").exists()
    assert (out / "commands.txt").exists()


def test_reviewer_package_generates_honest_claims(tmp_path):
    result = run_reviewer_package(tmp_path / "reviewer", include_benchmark=False)

    out = Path(result["output_dir"])
    assert (out / "one_page.md").exists()
    assert (out / "demo_script.md").exists()
    assert (out / "honest_claims.json").exists()

    claims = json.loads((out / "honest_claims.json").read_text(encoding="utf-8"))
    assert claims["confirmed_real_bugs"] == 0
    assert claims["production_ready"] is False
