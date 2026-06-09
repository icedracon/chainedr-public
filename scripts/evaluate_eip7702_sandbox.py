"""
Evaluate the EIP-7702 / ERC-7562 validation-sandbox benchmark.

This script is intentionally independent from the legacy Hunter benchmark
runner. It scores the v3 plugin detector output that carries sandbox metadata,
which is the evidence path needed for the paper track.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from detector_plugin import ScanOptions  # noqa: E402
from eip7702_validation import EIP7702ValidationDetector  # noqa: E402
from project_context import discover_project  # noqa: E402


def _load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "samples" not in data:
        raise ValueError(f"manifest must contain a samples array: {path}")
    return data


def _scan_sample(path: Path) -> tuple[list[dict[str, Any]], float]:
    ctx = discover_project(path)
    detector = EIP7702ValidationDetector()
    opts = ScanOptions(use_external_tools=False, use_slither=False, use_ast=False)
    start = time.perf_counter()
    result = detector._timed_scan(ctx, opts)
    elapsed = time.perf_counter() - start
    return [finding.to_dict() for finding in result.findings], elapsed


def _rule_hits(findings: list[dict[str, Any]]) -> set[str]:
    return {finding.get("rule_id", "") for finding in findings if finding.get("rule_id")}


def _matching_finding(findings: list[dict[str, Any]], rule_id: str) -> dict[str, Any] | None:
    for finding in findings:
        if finding.get("rule_id") == rule_id:
            return finding
    return None


def _safe_div(num: float, denom: float) -> float:
    return round(num / denom, 4) if denom else 0.0


def _repo_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def evaluate(corpus_dir: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)

    per_sample: list[dict[str, Any]] = []
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {
        "expected": 0,
        "detected": 0,
        "missed": 0,
        "wrong_class": 0,
    })

    true_positive = false_positive = true_negative = false_negative = wrong_class = 0
    boundary_expected = boundary_correct = 0
    trace_expected = trace_present = 0

    for sample in manifest["samples"]:
        target = corpus_dir / sample["path"]
        if not target.exists():
            raise FileNotFoundError(f"sample target not found: {target}")

        findings, elapsed = _scan_sample(target)
        detected_rules = sorted(_rule_hits(findings))
        expected_rule = sample.get("expected_rule")
        expected_boundary = sample.get("expected_sandbox_boundary") or sample.get("sandbox_boundary")

        status = "TRUE_NEGATIVE"
        matched: dict[str, Any] | None = None

        if expected_rule:
            per_rule[expected_rule]["expected"] += 1
            matched = _matching_finding(findings, expected_rule)
            if matched:
                true_positive += 1
                per_rule[expected_rule]["detected"] += 1
                status = "DETECTED"
                if expected_boundary:
                    boundary_expected += 1
                    boundary = matched.get("metadata", {}).get("sandbox_boundary")
                    if boundary == expected_boundary:
                        boundary_correct += 1
                trace_expected += 1
                trace = matched.get("metadata", {}).get("pre_behavior_trace")
                if trace:
                    trace_present += 1
            elif findings:
                wrong_class += 1
                per_rule[expected_rule]["wrong_class"] += 1
                status = "WRONG_CLASS"
            else:
                false_negative += 1
                per_rule[expected_rule]["missed"] += 1
                status = "MISSED"
        else:
            if findings:
                false_positive += 1
                status = "FALSE_POSITIVE"
            else:
                true_negative += 1

        per_sample.append({
            "id": sample["id"],
            "path": sample["path"],
            "label": sample["label"],
            "expected_rule": expected_rule,
            "expected_sandbox_boundary": expected_boundary,
            "status": status,
            "detected_rules": detected_rules,
            "finding_count": len(findings),
            "runtime_s": round(elapsed, 4),
            "findings": findings,
        })

    precision = _safe_div(true_positive, true_positive + false_positive + wrong_class)
    recall = _safe_div(true_positive, true_positive + false_negative + wrong_class)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    specificity = _safe_div(true_negative, true_negative + false_positive)
    accuracy = _safe_div(true_positive + true_negative, len(per_sample))

    return {
        "benchmark": manifest.get("name", corpus_dir.name),
        "version": manifest.get("version", "unknown"),
        "detector": manifest.get("detector", "eip7702_validation"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpus_dir": _repo_path(corpus_dir),
        "manifest": _repo_path(manifest_path),
        "summary": {
            "samples": len(per_sample),
            "vulnerable_or_expected_positive": true_positive + false_negative + wrong_class,
            "fixed_or_benign_controls": true_negative + false_positive,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "wrong_class": wrong_class,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": specificity,
            "accuracy": accuracy,
            "sandbox_boundary_accuracy": _safe_div(boundary_correct, boundary_expected),
            "pre_behavior_trace_coverage": _safe_div(trace_present, trace_expected),
        },
        "per_rule": dict(sorted(per_rule.items())),
        "per_sample": per_sample,
    }


def _print_summary(result: dict[str, Any]) -> None:
    summary = result["summary"]
    metrics = result["metrics"]
    print(f"Benchmark: {result['benchmark']} v{result['version']}")
    print(f"Detector:  {result['detector']}")
    print(f"Samples:   {summary['samples']}")
    print(
        "Counts:    "
        f"TP={summary['true_positive']} "
        f"FP={summary['false_positive']} "
        f"TN={summary['true_negative']} "
        f"FN={summary['false_negative']} "
        f"WRONG={summary['wrong_class']}"
    )
    print(
        "Metrics:   "
        f"precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} "
        f"f1={metrics['f1']:.4f} "
        f"specificity={metrics['specificity']:.4f}"
    )
    print(
        "Metadata:  "
        f"boundary_accuracy={metrics['sandbox_boundary_accuracy']:.4f} "
        f"trace_coverage={metrics['pre_behavior_trace_coverage']:.4f}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate ChainEDR EIP-7702 validation-sandbox benchmark."
    )
    parser.add_argument(
        "--corpus",
        default=str(REPO_ROOT / "benchmarks" / "eip7702_sandbox"),
        help="Benchmark corpus directory.",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Benchmark manifest path. Defaults to <corpus>/manifest.json.",
    )
    parser.add_argument("-o", "--output", default=None, help="Write JSON results to this path.")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if any sample is missed or false-positive.")
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus).resolve()
    manifest_path = Path(args.manifest).resolve() if args.manifest else corpus_dir / "manifest.json"

    result = evaluate(corpus_dir, manifest_path)
    _print_summary(result)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Results:   {output}")

    if args.strict:
        summary = result["summary"]
        if summary["false_positive"] or summary["false_negative"] or summary["wrong_class"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
