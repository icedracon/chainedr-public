#!/usr/bin/env python3
"""Evaluate external/blind ChainEDR Analyzer benchmark manifests.

The internal benchmark proves regression stability. This runner is for the next
production milestone: samples collected outside the repository's training
fixtures. It supports two modes:

- unlabeled/blind: record detections and immutable content hashes;
- labeled: compute TP/FP/TN/FN once expected labels are revealed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from eip7702_detector import EIP7702Detector  # noqa: E402


_ALLOWED_DETECTORS = {"eip7702", "eip7702_validation"}
_ALLOWED_LABELS = {"vulnerable", "fixed", "benign", "safe", "negative"}
_NEGATIVE_LABELS = {"fixed", "benign", "safe", "negative"}


@dataclass
class _Detection:
    rules: set[str]
    findings: list[dict[str, Any]]
    runtime_s: float


class _ValidationShim:
    def __init__(self, root: Path) -> None:
        from eip7702_validation import EIP7702ValidationDetector

        self._root = root
        self._detector = EIP7702ValidationDetector()

    def detect(self, source: str, path: Path) -> list[dict[str, Any]]:
        from eip7702_validation import _strip_comments

        @dataclass
        class _FakeCtx:
            root: Path

        ctx = _FakeCtx(root=self._root)
        findings = self._detector._analyze(_strip_comments(source), path, ctx)
        return [finding.to_dict() for finding in findings]


def _load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    _validate_manifest(data, path)
    return data


def _validate_manifest(data: dict[str, Any], path: Path) -> None:
    samples = data.get("samples")
    if not isinstance(samples, list):
        raise ValueError(f"blind benchmark manifest must contain a samples array: {path}")
    if not samples:
        raise ValueError(f"blind benchmark manifest must contain at least one sample: {path}")

    seen_ids: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise ValueError(f"sample #{index} must be an object")

        sample_id = str(sample.get("id") or "").strip()
        if not sample_id:
            raise ValueError(f"sample #{index} is missing non-empty id")
        if sample_id in seen_ids:
            raise ValueError(f"duplicate sample id: {sample_id}")
        seen_ids.add(sample_id)

        sample_path = sample.get("path")
        if not isinstance(sample_path, str) or not sample_path.strip():
            raise ValueError(f"sample {sample_id} is missing non-empty path")
        if Path(sample_path).is_absolute():
            raise ValueError(f"sample {sample_id} path must be relative: {sample_path}")

        detector = sample.get("detector_under_test") or sample.get("detector")
        if detector not in _ALLOWED_DETECTORS:
            raise ValueError(
                f"sample {sample_id} has unsupported detector_under_test={detector!r}; "
                f"expected one of {sorted(_ALLOWED_DETECTORS)}"
            )

        if not (sample.get("rule_under_test") or sample.get("expected_rule")):
            raise ValueError(f"sample {sample_id} must declare rule_under_test or expected_rule")

        label = sample.get("label")
        normalized_label = str(label).lower() if label is not None else None
        if normalized_label is not None and normalized_label not in _ALLOWED_LABELS:
            raise ValueError(
                f"sample {sample_id} has unsupported label={label!r}; "
                f"expected one of {sorted(_ALLOWED_LABELS)}"
            )
        expected_rule = sample.get("expected_rule")
        if normalized_label == "vulnerable" and not expected_rule:
            raise ValueError(f"vulnerable sample {sample_id} must declare expected_rule")
        if normalized_label in _NEGATIVE_LABELS and expected_rule:
            raise ValueError(
                f"negative/control sample {sample_id} must put the evaluated rule in "
                "rule_under_test, not expected_rule"
            )


def _detector_family(sample: dict[str, Any]) -> str:
    detector = sample.get("detector_under_test") or sample.get("detector")
    if detector:
        return str(detector)
    rule = str(sample.get("rule_under_test") or sample.get("expected_rule") or "")
    if rule.startswith("AA7562"):
        return "eip7702_validation"
    return "eip7702"


def _read_sample(corpus_dir: Path, sample: dict[str, Any]) -> tuple[Path, str]:
    rel = Path(sample["path"])
    target = (corpus_dir / rel).resolve()
    corpus = corpus_dir.resolve()
    if not target.is_relative_to(corpus):
        raise ValueError(f"sample path escapes corpus: {sample['path']}")
    if not target.exists():
        raise FileNotFoundError(f"sample target not found: {target}")
    return target, target.read_text(encoding="utf-8", errors="replace")


def _detect(
    source: str,
    path: Path,
    sample: dict[str, Any],
    eip7702: EIP7702Detector,
    validation: _ValidationShim,
) -> _Detection:
    detector = _detector_family(sample)
    rule_under_test = sample.get("rule_under_test")
    start = time.perf_counter()

    if detector == "eip7702":
        if rule_under_test:
            findings = [
                finding.to_dict()
                for finding in eip7702.check_selective(source, [str(rule_under_test)])
            ]
        else:
            findings = [finding.to_dict() for finding in eip7702.check(source)]
        rules = {
            finding.get("check") or finding.get("rule_id") or finding.get("check_id")
            for finding in findings
        }
    elif detector == "eip7702_validation":
        findings = validation.detect(source, path)
        if rule_under_test:
            findings = [
                finding for finding in findings
                if finding.get("rule_id") == rule_under_test
            ]
        rules = {finding.get("rule_id") for finding in findings}
    else:
        raise ValueError(f"unsupported detector_under_test={detector!r}")

    return _Detection(
        rules={str(rule) for rule in rules if rule},
        findings=findings,
        runtime_s=time.perf_counter() - start,
    )


def _score_sample(sample: dict[str, Any], detected_rules: set[str]) -> tuple[str, str | None]:
    expected_rule = sample.get("expected_rule")
    label = str(sample.get("label") or "").lower()
    has_label = bool(expected_rule or label in {"vulnerable", "fixed", "benign", "safe", "negative"})
    if not has_label:
        return ("UNLABELED_DETECTED" if detected_rules else "UNLABELED_CLEAN"), None

    if expected_rule:
        if expected_rule in detected_rules:
            return "TRUE_POSITIVE", str(expected_rule)
        if detected_rules:
            return "WRONG_CLASS", str(expected_rule)
        return "FALSE_NEGATIVE", str(expected_rule)

    if detected_rules:
        return "FALSE_POSITIVE", sample.get("rule_under_test")
    return "TRUE_NEGATIVE", sample.get("rule_under_test")


def _triage_status(sample: dict[str, Any], status: str) -> str:
    if status == "UNLABELED_DETECTED":
        return "needs_label_reveal"
    if status == "UNLABELED_CLEAN":
        return "needs_negative_control_review"
    if status in {"FALSE_POSITIVE", "FALSE_NEGATIVE", "WRONG_CLASS"}:
        return "needs_investigation"
    return "scored"


def _triage_note(status: str) -> str:
    notes = {
        "UNLABELED_DETECTED": "Detection occurred before labels were revealed; freeze the hash and request independent labeling.",
        "UNLABELED_CLEAN": "No detection occurred before labels were revealed; freeze the hash and confirm it is a negative/control sample.",
        "FALSE_POSITIVE": "Labeled-safe sample produced a detection; triage source context before counting as a scanner regression.",
        "FALSE_NEGATIVE": "Expected rule was not detected; inspect whether the sample is in scope and whether the rule needs improvement.",
        "WRONG_CLASS": "A detection occurred, but not for the expected rule; review taxonomy and detector routing.",
        "TRUE_POSITIVE": "Expected rule was detected on a labeled vulnerable sample.",
        "TRUE_NEGATIVE": "No detection occurred on a labeled negative/control sample.",
    }
    return notes.get(status, "Review sample manually.")


def _safe_div(num: float, denom: float) -> float:
    return round(num / denom, 4) if denom else 0.0


def _percentile(values: list[float], percent: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((percent / 100) * (len(ordered) - 1))))
    return ordered[index]


def _expected_matrix_key(sample: dict[str, Any]) -> str:
    expected_rule = sample.get("expected_rule")
    if expected_rule:
        return str(expected_rule)
    rule = sample.get("rule_under_test") or _detector_family(sample)
    label = str(sample.get("label") or "").lower()
    if label in _NEGATIVE_LABELS:
        return f"NEGATIVE:{rule}"
    return f"UNLABELED:{rule}"


def _detected_matrix_key(detected_rules: set[str]) -> str:
    if not detected_rules:
        return "NO_DETECTION"
    return "|".join(sorted(detected_rules))


def _label_bucket(sample: dict[str, Any]) -> str:
    label = str(sample.get("label") or "").lower()
    if label:
        return label
    if sample.get("expected_rule"):
        return "implicit_vulnerable"
    return "unlabeled"


def _with_rule_metrics(counts: dict[str, int]) -> dict[str, Any]:
    tp = counts.get("tp", 0)
    fp = counts.get("fp", 0)
    tn = counts.get("tn", 0)
    fn = counts.get("fn", 0)
    wrong = counts.get("wrong_class", 0)
    precision = _safe_div(tp, tp + fp + wrong)
    recall = _safe_div(tp, tp + fn + wrong)
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": _safe_div(2 * precision * recall, precision + recall),
        "specificity": _safe_div(tn, tn + fp),
    }


def evaluate(corpus_dir: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    eip7702 = EIP7702Detector()
    validation = _ValidationShim(corpus_dir)
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
        "wrong_class": 0,
    })
    confusion_matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    detected_rule_counts: dict[str, int] = defaultdict(int)
    label_inventory: dict[str, Any] = {
        "raw_labels": defaultdict(int),
        "by_detector": defaultdict(lambda: defaultdict(int)),
    }
    runtimes: list[float] = []
    per_sample: list[dict[str, Any]] = []
    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
        "wrong_class": 0,
        "unlabeled_detected": 0,
        "unlabeled_clean": 0,
    }

    for sample in manifest["samples"]:
        target, source = _read_sample(corpus_dir, sample)
        detection = _detect(source, target, sample, eip7702, validation)
        status, scored_rule = _score_sample(sample, detection.rules)
        expected_key = _expected_matrix_key(sample)
        detected_key = _detected_matrix_key(detection.rules)
        detector_family = _detector_family(sample)
        label_bucket = _label_bucket(sample)
        confusion_matrix[expected_key][detected_key] += 1
        runtimes.append(detection.runtime_s)
        label_inventory["raw_labels"][label_bucket] += 1
        label_inventory["by_detector"][detector_family][label_bucket] += 1
        for rule in detection.rules:
            detected_rule_counts[rule] += 1

        if status == "TRUE_POSITIVE":
            counts["true_positive"] += 1
            per_rule[scored_rule or "UNKNOWN"]["tp"] += 1
        elif status == "FALSE_POSITIVE":
            counts["false_positive"] += 1
            per_rule[scored_rule or "GLOBAL_CONTROL"]["fp"] += 1
        elif status == "TRUE_NEGATIVE":
            counts["true_negative"] += 1
            per_rule[scored_rule or "GLOBAL_CONTROL"]["tn"] += 1
        elif status == "FALSE_NEGATIVE":
            counts["false_negative"] += 1
            per_rule[scored_rule or "UNKNOWN"]["fn"] += 1
        elif status == "WRONG_CLASS":
            counts["wrong_class"] += 1
            per_rule[scored_rule or "UNKNOWN"]["wrong_class"] += 1
        elif status == "UNLABELED_DETECTED":
            counts["unlabeled_detected"] += 1
        elif status == "UNLABELED_CLEAN":
            counts["unlabeled_clean"] += 1

        per_sample.append({
            "id": sample.get("id") or sample["path"],
            "path": sample["path"],
            "detector_under_test": detector_family,
            "scanned_rule_scope": sample.get("rule_under_test") or "all_rules",
            "label": sample.get("label"),
            "expected_rule": sample.get("expected_rule"),
            "rule_under_test": sample.get("rule_under_test"),
            "status": status,
            "triage_status": _triage_status(sample, status),
            "triage_note": _triage_note(status),
            "detected_rules": sorted(detection.rules),
            "finding_count": len(detection.findings),
            "content_sha256": hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest(),
            "runtime_s": round(detection.runtime_s, 6),
            "findings": detection.findings,
        })

    tp = counts["true_positive"]
    fp = counts["false_positive"]
    tn = counts["true_negative"]
    fn = counts["false_negative"]
    wrong = counts["wrong_class"]
    labeled = tp + fp + tn + fn + wrong
    precision = _safe_div(tp, tp + fp + wrong)
    recall = _safe_div(tp, tp + fn + wrong)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    runtime_total = sum(runtimes)

    return {
        "benchmark": manifest.get("name", "external_blind_benchmark"),
        "version": manifest.get("version", "unknown"),
        "evaluation_mode": "blind_external",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpus_dir": str(corpus_dir.resolve()),
        "manifest": str(manifest_path.resolve()),
        "manifest_contract": {
            "schema": "schemas/chainedr-blind-benchmark-manifest.schema.json",
            "samples_validated": len(manifest["samples"]),
            "labels_required_for_scoring": False,
        },
        "summary": {
            "samples": len(per_sample),
            "labeled_samples": labeled,
            **counts,
        },
        "label_inventory": {
            "raw_labels": dict(sorted(label_inventory["raw_labels"].items())),
            "by_detector": {
                detector: dict(sorted(labels.items()))
                for detector, labels in sorted(label_inventory["by_detector"].items())
            },
        },
        "runtime": {
            "total_s": round(runtime_total, 6),
            "mean_s": round(runtime_total / len(runtimes), 6) if runtimes else 0.0,
            "max_s": round(max(runtimes) if runtimes else 0.0, 6),
            "p95_s": round(_percentile(runtimes, 95), 6),
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": _safe_div(tn, tn + fp),
            "accuracy": _safe_div(tp + tn, labeled),
        },
        "per_rule": dict(sorted(per_rule.items())),
        "per_rule_metrics": {
            rule: _with_rule_metrics(rule_counts)
            for rule, rule_counts in sorted(per_rule.items())
        },
        "detected_rule_counts": dict(sorted(detected_rule_counts.items())),
        "confusion_matrix": {
            expected: dict(sorted(detected.items()))
            for expected, detected in sorted(confusion_matrix.items())
        },
        "per_sample": per_sample,
    }


def _print_summary(result: dict[str, Any]) -> None:
    summary = result["summary"]
    metrics = result["metrics"]
    print(f"Benchmark: {result['benchmark']} v{result['version']}")
    print(f"Mode:      {result['evaluation_mode']}")
    print(f"Samples:   {summary['samples']} ({summary['labeled_samples']} labeled)")
    print(
        "Counts:    "
        f"TP={summary['true_positive']} FP={summary['false_positive']} "
        f"TN={summary['true_negative']} FN={summary['false_negative']} "
        f"WRONG={summary['wrong_class']} "
        f"UNLABELED={summary['unlabeled_detected'] + summary['unlabeled_clean']}"
    )
    print(
        "Metrics:   "
        f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
        f"f1={metrics['f1']:.4f} specificity={metrics['specificity']:.4f}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a blind external ChainEDR benchmark manifest.")
    parser.add_argument("--corpus", required=True, help="External benchmark corpus directory.")
    parser.add_argument("--manifest", required=True, help="External benchmark manifest JSON.")
    parser.add_argument("-o", "--output", default=None, help="Write JSON result.")
    parser.add_argument("--strict", action="store_true", help="Fail on FP, FN, or wrong-class labeled samples.")
    parser.add_argument("--require-labels", action="store_true", help="Fail if any sample is unlabeled.")
    args = parser.parse_args(argv)

    result = evaluate(Path(args.corpus), Path(args.manifest))
    _print_summary(result)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Results:   {output}")

    summary = result["summary"]
    if args.require_labels and summary["samples"] != summary["labeled_samples"]:
        return 1
    if args.strict and (
        summary["false_positive"]
        or summary["false_negative"]
        or summary["wrong_class"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
