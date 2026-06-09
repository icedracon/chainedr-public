"""Focused Part 2 tooling regressions."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_bug_benchmark_empty_manifest_is_unknown_not_zero(tmp_path):
    evaluator = _load_script("evaluate_real_7702_bugs.py")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "name": "real_7702_bugs", "cases": []}),
        encoding="utf-8",
    )

    result = evaluator.evaluate_manifest(manifest, repo_root=tmp_path)

    assert result["status"] == "empty_manifest"
    assert result["samples"] == 0
    assert result["recall"] is None


def test_real_bug_benchmark_matches_expected_rule(tmp_path):
    evaluator = _load_script("evaluate_real_7702_bugs.py")
    source = tmp_path / "DelegationTarget.sol"
    source.write_text(
        """
        pragma solidity ^0.8.20;
        contract DelegationTarget7702 {
            function enter() external view returns (bool) {
                return tx.origin == msg.sender;
            }
        }
        """,
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({
            "version": 1,
            "name": "real_7702_bugs",
            "cases": [{
                "id": "synthetic_test_only",
                "source": str(source),
                "expected_rules": ["AA7702-001"],
            }],
        }),
        encoding="utf-8",
    )

    result = evaluator.evaluate_manifest(manifest, repo_root=tmp_path)

    assert result["status"] == "ok"
    assert result["samples"] == 1
    assert result["recall"] == 1.0
    assert result["results"][0]["matched_rules"] == ["AA7702-001"]


def test_focus_loop_alerts_only_on_confirmed_live_poc(tmp_path):
    focus_loop = _load_script("focus_loop.py")
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "DelegationTarget.sol").write_text(
        """
        pragma solidity ^0.8.20;
        contract DelegationTarget7702 {
            function enter() external view returns (bool) {
                return tx.origin == msg.sender;
            }
        }
        """,
        encoding="utf-8",
    )
    manifest = tmp_path / "targets.json"
    manifest.write_text(
        json.dumps({
            "targets": [{
                "name": "demo",
                "path": str(source_dir),
                "address": "0x0000000000000000000000000000000000000772",
                "chain_id": 1,
                "proofs": [
                    {"rule_id": "AA7702-001", "confirmed": True, "live_impact": False, "poc": "poc/a.t.sol"},
                    {"rule_id": "AA7702-011", "confirmed": True, "live_impact": True, "calldata": "0xdeadbeef"},
                ],
            }],
        }),
        encoding="utf-8",
    )

    result = focus_loop.run_focus_loop(manifest, repo_root=tmp_path)

    assert result["summary"]["static_candidates"] >= 1
    assert result["summary"]["proofs"] == 2
    assert result["summary"]["alerts"] == 1
    assert result["alerts"][0]["rule_id"] == "AA7702-011"
    assert result["results"][0]["rejected_proofs"][0]["status"] == "not_alertable"
