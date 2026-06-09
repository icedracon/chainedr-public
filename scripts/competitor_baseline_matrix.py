#!/usr/bin/env python3
"""Build a fair competitor-baseline matrix for ChainEDR Analyzer.

This does not pretend that missing tools were run. It records environment
availability, the intended comparison scope, and optional ChainEDR benchmark
results so paper/product claims can distinguish "measured" from "planned".
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


TOOL_MATRIX = [
    {
        "tool": "ChainEDR Analyzer",
        "binary": None,
        "comparison_role": "subject",
        "scope": "EIP-7702 / ERC-4337 / ERC-7562 assumptions and proof guidance",
        "run_status": "available",
    },
    {
        "tool": "Slither",
        "binary": "slither",
        "comparison_role": "baseline",
        "scope": "generic Solidity static analysis",
    },
    {
        "tool": "Semgrep",
        "binary": "semgrep",
        "comparison_role": "baseline",
        "scope": "custom Solidity pattern rules",
    },
    {
        "tool": "CodeQL",
        "binary": "codeql",
        "comparison_role": "baseline",
        "scope": "query-based source analysis",
    },
    {
        "tool": "Aderyn",
        "binary": "aderyn",
        "comparison_role": "baseline",
        "scope": "Solidity static audit checks",
    },
    {
        "tool": "Mythril",
        "binary": "myth",
        "comparison_role": "baseline",
        "scope": "symbolic execution / bytecode-oriented analysis",
    },
    {
        "tool": "ERC-4337 Checkers",
        "binary": None,
        "comparison_role": "domain_baseline",
        "scope": "EntryPoint/UserOperation validation checks where available",
        "run_status": "manual_baseline_needed",
    },
]


def _run_version(binary: str) -> str:
    for args in ([binary, "--version"], [binary, "version"]):
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        text = (proc.stdout or proc.stderr).strip()
        if text:
            return text.splitlines()[0][:160]
    return "unknown"


def collect_inventory(
    which: Callable[[str], str | None] = shutil.which,
    version_runner: Callable[[str], str] = _run_version,
) -> list[dict]:
    inventory = []
    for item in TOOL_MATRIX:
        row = dict(item)
        binary = row.get("binary")
        if not binary:
            row.setdefault("available", row["tool"] == "ChainEDR Analyzer")
            row.setdefault("path", None)
            row.setdefault("version", "repo")
            row.setdefault("run_status", row.get("run_status", "available"))
            row.setdefault("measured", False)
            row.setdefault("evidence_level", "subject_without_result")
            inventory.append(row)
            continue
        path = which(binary)
        row["available"] = bool(path)
        row["path"] = path
        row["version"] = version_runner(binary) if path else "not installed"
        row["run_status"] = "ready_to_run" if path else "not_installed"
        row["measured"] = False
        row["evidence_level"] = "installed_not_measured" if path else "not_available"
        inventory.append(row)
    return inventory


def _annotate_evidence(inventory: list[dict], *, has_chainedr_result: bool) -> list[dict]:
    annotated = []
    for item in inventory:
        row = dict(item)
        if row.get("tool") == "ChainEDR Analyzer":
            row["measured"] = bool(has_chainedr_result)
            row["evidence_level"] = (
                "measured_subject" if has_chainedr_result else "subject_without_result"
            )
        elif row.get("run_status") == "manual_baseline_needed":
            row["measured"] = False
            row["evidence_level"] = "manual_baseline_needed"
        elif row.get("run_status") == "ready_to_run":
            row["measured"] = False
            row["evidence_level"] = "installed_not_measured"
        elif row.get("run_status") == "not_installed":
            row["measured"] = False
            row["evidence_level"] = "not_available"
        else:
            row.setdefault("measured", False)
            row.setdefault("evidence_level", "not_measured")
        annotated.append(row)
    return annotated


def build_matrix(
    *,
    benchmark_result: dict | None = None,
    inventory: list[dict] | None = None,
) -> dict:
    benchmark_summary = None
    if benchmark_result:
        benchmark_summary = {
            "benchmark": benchmark_result.get("benchmark"),
            "version": benchmark_result.get("version"),
            "evaluation_mode": benchmark_result.get("evaluation_mode"),
            "summary": benchmark_result.get("summary") or benchmark_result.get("overall"),
            "metrics": benchmark_result.get("metrics"),
        }
    raw_inventory = collect_inventory() if inventory is None else inventory
    tools = _annotate_evidence(
        raw_inventory,
        has_chainedr_result=benchmark_summary is not None,
    )
    measured_tools = [tool["tool"] for tool in tools if tool.get("measured")]
    return {
        "name": "ChainEDR competitor baseline matrix",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "claim_policy": (
            "Only tools with measured=true and recorded result artifacts may be "
            "cited as measured baselines. Installed tools without scored outputs "
            "are environment inventory, not comparative evidence."
        ),
        "chainedr_result": benchmark_summary,
        "tools": tools,
        "measured_tools": measured_tools,
        "next_required_evidence": [
            "run each available baseline on the same frozen external corpus",
            "store raw outputs and command lines",
            "score each tool against the same labels and rule scope",
            "separate generic findings from EIP-7702/ERC-4337/ERC-7562-specific findings",
        ],
    }


def write_outputs(matrix: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "competitor_baseline_matrix.json"
    md_path = output_dir / "competitor_baseline_matrix.md"
    json_path.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(_markdown(matrix), encoding="utf-8")
    return json_path, md_path


def _markdown(matrix: dict) -> str:
    lines = [
        "# ChainEDR Competitor Baseline Matrix",
        "",
        matrix["claim_policy"],
        "",
        "| Tool | Role | Scope | Status | Evidence | Version |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for tool in matrix["tools"]:
        lines.append(
            "| {tool} | {role} | {scope} | {status} | {evidence} | {version} |".format(
                tool=tool["tool"],
                role=tool.get("comparison_role", ""),
                scope=tool.get("scope", ""),
                status=tool.get("run_status", ""),
                evidence=tool.get("evidence_level", ""),
                version=str(tool.get("version", "")).replace("|", "\\|"),
            )
        )
    lines.extend(["", "## Measured Tools", ""])
    if matrix.get("measured_tools"):
        for tool in matrix["measured_tools"]:
            lines.append(f"- {tool}")
    else:
        lines.append("- None yet. Treat this file as environment inventory only.")
    lines.extend(["", "## Next Required Evidence", ""])
    for item in matrix["next_required_evidence"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build ChainEDR competitor baseline matrix.")
    parser.add_argument("--benchmark-result", default=None, help="Optional ChainEDR benchmark result JSON.")
    parser.add_argument("--output-dir", default="paper/results", help="Directory for JSON/Markdown outputs.")
    args = parser.parse_args(argv)

    benchmark_result = None
    if args.benchmark_result:
        benchmark_result = json.loads(Path(args.benchmark_result).read_text(encoding="utf-8"))
    matrix = build_matrix(benchmark_result=benchmark_result)
    json_path, md_path = write_outputs(matrix, Path(args.output_dir))
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
