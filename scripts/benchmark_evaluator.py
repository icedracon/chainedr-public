#!/usr/bin/env python3
"""Evaluate the full ChainEDR EIP-7702 benchmark corpus."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from eip7702_detector import EIP7702Detector  # noqa: E402


@dataclass
class _DetectionResult:
    rule_ids: set[str]
    runtime_s: float


class _ValidationShim:
    """Run EIP7702ValidationDetector against one source file."""

    def __init__(self) -> None:
        from eip7702_validation import EIP7702ValidationDetector

        self._detector = EIP7702ValidationDetector()

    def rule_ids(self, source: str, path: Path) -> set[str]:
        from eip7702_validation import _strip_comments

        @dataclass
        class _FakeCtx:
            root: Path

        ctx = _FakeCtx(root=path.parent)
        findings = self._detector._analyze(_strip_comments(source), path, ctx)
        return {finding.rule_id for finding in findings}


def _load_labels(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data.get("samples")
    if not isinstance(samples, list):
        raise ValueError(f"labels file must contain a samples array: {path}")
    return data


def _detector_family(sample: dict[str, Any]) -> str:
    detector = sample.get("detector_under_test")
    if detector:
        return detector
    rule = sample.get("rule_under_test") or sample.get("expected_rule") or ""
    if rule.startswith("AA7562"):
        return "eip7702_validation"
    if rule.startswith("AA7702"):
        return "eip7702"
    return "eip7702_validation"


def _detect_rules(
    source: str,
    path: Path,
    sample: dict[str, Any],
    eip7702_detector: EIP7702Detector,
    validation_detector: _ValidationShim,
) -> _DetectionResult:
    detector = _detector_family(sample)
    rule_under_test = sample.get("rule_under_test") or sample.get("expected_rule")

    start = time.perf_counter()
    if detector == "eip7702":
        if rule_under_test:
            findings = eip7702_detector.check_selective(source, [rule_under_test])
        else:
            findings = eip7702_detector.check(source)
        rule_ids = {finding.check_id for finding in findings}
    elif detector == "eip7702_validation":
        rule_ids = validation_detector.rule_ids(source, path)
        if rule_under_test:
            rule_ids = {rule for rule in rule_ids if rule == rule_under_test}
    else:
        raise ValueError(f"unknown detector_under_test={detector!r} for {sample.get('id')}")

    return _DetectionResult(rule_ids=rule_ids, runtime_s=time.perf_counter() - start)


def _safe_div(num: float, denom: float) -> float:
    return round(num / denom, 4) if denom else 0.0


def _repo_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(resolved)


def evaluate(corpus_dir: Path, labels_path: Path) -> dict[str, Any]:
    labels = _load_labels(labels_path)
    eip7702_detector = EIP7702Detector()
    validation_detector = _ValidationShim()

    per_rule: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "samples": [],
        }
    )
    per_sample: list[dict[str, Any]] = []

    tp = fp = tn = fn = wrong_class = 0
    total_runtime = 0.0

    for sample in labels["samples"]:
        sample_path = corpus_dir / sample["path"]
        if not sample_path.exists():
            raise FileNotFoundError(f"sample target not found: {sample_path}")

        source = sample_path.read_text(encoding="utf-8", errors="replace")
        detection = _detect_rules(
            source,
            sample_path,
            sample,
            eip7702_detector,
            validation_detector,
        )
        detected_rules = sorted(detection.rule_ids)
        total_runtime += detection.runtime_s

        expected_rule = sample.get("expected_rule")
        rule_under_test = sample.get("rule_under_test") or expected_rule or "GLOBAL_CONTROL"
        status = "TRUE_NEGATIVE"

        if sample.get("label") == "vulnerable":
            if not expected_rule:
                raise ValueError(f"vulnerable sample missing expected_rule: {sample.get('id')}")
            if expected_rule in detection.rule_ids:
                status = "TRUE_POSITIVE"
                tp += 1
                per_rule[expected_rule]["tp"] += 1
            elif detection.rule_ids:
                status = "WRONG_CLASS"
                wrong_class += 1
                per_rule[expected_rule]["fn"] += 1
            else:
                status = "FALSE_NEGATIVE"
                fn += 1
                per_rule[expected_rule]["fn"] += 1
        else:
            if detection.rule_ids:
                status = "FALSE_POSITIVE"
                fp += 1
                per_rule[rule_under_test]["fp"] += 1
            else:
                tn += 1
                per_rule[rule_under_test]["tn"] += 1

        sample_result = {
            "id": sample["id"],
            "path": sample["path"],
            "label": sample["label"],
            "detector_under_test": _detector_family(sample),
            "expected_rule": expected_rule,
            "rule_under_test": sample.get("rule_under_test"),
            "status": status,
            "detected_rules": detected_rules,
            "runtime_s": round(detection.runtime_s, 6),
        }
        per_sample.append(sample_result)
        per_rule[rule_under_test]["samples"].append({
            "id": sample["id"],
            "status": status,
            "detected_rules": detected_rules,
        })

    precision = _safe_div(tp, tp + fp + wrong_class)
    recall = _safe_div(tp, tp + fn + wrong_class)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    specificity = _safe_div(tn, tn + fp)
    accuracy = _safe_div(tp + tn, len(per_sample))

    formatted_per_rule = {}
    for rule_id, data in sorted(per_rule.items()):
        rule_tp = data["tp"]
        rule_fp = data["fp"]
        rule_tn = data["tn"]
        rule_fn = data["fn"]
        rule_precision = _safe_div(rule_tp, rule_tp + rule_fp)
        rule_recall = _safe_div(rule_tp, rule_tp + rule_fn)
        rule_f1 = _safe_div(2 * rule_precision * rule_recall, rule_precision + rule_recall)
        formatted_per_rule[rule_id] = {
            "tp": rule_tp,
            "fp": rule_fp,
            "tn": rule_tn,
            "fn": rule_fn,
            "precision": rule_precision,
            "recall": rule_recall,
            "f1": rule_f1,
            "samples": data["samples"],
        }

    return {
        "benchmark": labels.get("name", corpus_dir.name),
        "version": labels.get("version", "unknown"),
        "evaluation_mode": "target_rule",
        "description": labels.get("description", ""),
        "corpus_dir": _repo_path(corpus_dir),
        "labels": _repo_path(labels_path),
        "overall": {
            "samples": len(per_sample),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "wrong_class": wrong_class,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": specificity,
            "accuracy": accuracy,
            "runtime_s": round(total_runtime, 6),
        },
        "per_detector": formatted_per_rule,
        "per_sample": per_sample,
    }


def _print_summary(result: dict[str, Any]) -> None:
    overall = result["overall"]
    print(f"Benchmark: {result['benchmark']} v{result['version']}")
    print(f"Mode:      {result['evaluation_mode']}")
    print(f"Samples:   {overall['samples']}")
    print(
        f"TP={overall['tp']} FP={overall['fp']} TN={overall['tn']} "
        f"FN={overall['fn']} WRONG={overall['wrong_class']} "
        f"P={overall['precision']:.2%} R={overall['recall']:.2%} "
        f"F1={overall['f1']:.2%} specificity={overall['specificity']:.2%}"
    )
    for rule_id, data in sorted(result["per_detector"].items()):
        status = "PASS" if data["fn"] == 0 and data["fp"] == 0 else "FAIL"
        print(
            f"  {rule_id}: {status} "
            f"(TP={data['tp']} FP={data['fp']} TN={data['tn']} FN={data['fn']})"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ChainEDR EIP-7702 benchmark evaluator")
    parser.add_argument(
        "--corpus",
        default=str(REPO_ROOT / "benchmarks" / "eip7702_sandbox"),
        help="Benchmark corpus directory.",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help="Benchmark labels path. Defaults to <corpus>/labels.json.",
    )
    parser.add_argument("-o", "--output", default=None, help="Write JSON results.")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on FP, FN, or wrong-class results.")
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus).resolve()
    labels_path = Path(args.labels).resolve() if args.labels else corpus_dir / "labels.json"
    result = evaluate(corpus_dir, labels_path)
    _print_summary(result)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Saved:     {output}")

    if args.strict:
        overall = result["overall"]
        if overall["fp"] or overall["fn"] or overall["wrong_class"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
