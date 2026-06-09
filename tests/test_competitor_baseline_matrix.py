"""Tests for the competitor baseline matrix scaffold."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from competitor_baseline_matrix import build_matrix, collect_inventory, write_outputs  # noqa: E402


def test_collect_inventory_records_available_and_missing_tools():
    paths = {"slither": "/bin/slither", "semgrep": "/bin/semgrep"}

    def fake_which(binary: str) -> str | None:
        return paths.get(binary)

    def fake_version(binary: str) -> str:
        return f"{binary} 1.2.3"

    inventory = collect_inventory(which=fake_which, version_runner=fake_version)
    by_tool = {item["tool"]: item for item in inventory}

    assert by_tool["ChainEDR Analyzer"]["run_status"] == "available"
    assert by_tool["ChainEDR Analyzer"]["evidence_level"] == "subject_without_result"
    assert by_tool["ChainEDR Analyzer"]["measured"] is False
    assert by_tool["Slither"]["run_status"] == "ready_to_run"
    assert by_tool["Slither"]["evidence_level"] == "installed_not_measured"
    assert by_tool["Slither"]["measured"] is False
    assert by_tool["Slither"]["version"] == "slither 1.2.3"
    assert by_tool["Aderyn"]["run_status"] == "not_installed"
    assert by_tool["Aderyn"]["evidence_level"] == "not_available"
    assert by_tool["ERC-4337 Checkers"]["run_status"] == "manual_baseline_needed"


def test_build_matrix_embeds_chainedr_benchmark_summary():
    benchmark = {
        "benchmark": "external_blind",
        "version": "0.1.0",
        "evaluation_mode": "blind_external",
        "summary": {"samples": 3, "true_positive": 1},
        "metrics": {"f1": 1.0},
    }

    matrix = build_matrix(benchmark_result=benchmark, inventory=[])

    assert matrix["chainedr_result"]["benchmark"] == "external_blind"
    assert matrix["chainedr_result"]["summary"]["samples"] == 3
    assert "measured baselines" in matrix["claim_policy"]
    assert matrix["measured_tools"] == []


def test_build_matrix_marks_chainedr_measured_when_result_is_present():
    benchmark = {
        "benchmark": "external_blind",
        "version": "0.1.0",
        "evaluation_mode": "blind_external",
        "summary": {"samples": 3, "true_positive": 1},
        "metrics": {"f1": 1.0},
    }
    inventory = [
        {
            "tool": "ChainEDR Analyzer",
            "comparison_role": "subject",
            "scope": "test",
            "run_status": "available",
            "available": True,
            "path": None,
            "version": "repo",
        }
    ]

    matrix = build_matrix(benchmark_result=benchmark, inventory=inventory)

    assert matrix["measured_tools"] == ["ChainEDR Analyzer"]
    assert matrix["tools"][0]["measured"] is True
    assert matrix["tools"][0]["evidence_level"] == "measured_subject"


def test_write_outputs_creates_json_and_markdown(tmp_path):
    matrix = build_matrix(inventory=[
        {
            "tool": "ChainEDR Analyzer",
            "comparison_role": "subject",
            "scope": "test",
            "run_status": "available",
            "version": "repo",
        }
    ])

    json_path, md_path = write_outputs(matrix, tmp_path)

    assert json.loads(json_path.read_text(encoding="utf-8"))["name"].startswith("ChainEDR")
    markdown = md_path.read_text(encoding="utf-8")
    assert "| ChainEDR Analyzer | subject | test | available | subject_without_result | repo |" in markdown
    assert "Treat this file as environment inventory only" in markdown
