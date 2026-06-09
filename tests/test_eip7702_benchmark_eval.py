"""Regression checks for the EIP-7702 sandbox benchmark evaluator."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from benchmark_evaluator import evaluate as evaluate_full_benchmark  # noqa: E402
from evaluate_eip7702_sandbox import evaluate as evaluate_validation_subset  # noqa: E402


def test_eip7702_sandbox_labels_are_consistent():
    corpus = ROOT / "benchmarks" / "eip7702_sandbox"
    labels = json.loads((corpus / "labels.json").read_text())

    assert labels["version"] == "1.1.0"
    assert len(labels["samples"]) == 57

    for sample in labels["samples"]:
        assert (corpus / sample["path"]).exists()
        if sample["label"] == "vulnerable":
            assert sample["expected_rule"]
            assert sample["rule_under_test"] == sample["expected_rule"]
        else:
            assert sample["expected_rule"] is None


def test_eip7702_full_benchmark_scores_all_labeled_samples_cleanly():
    corpus = ROOT / "benchmarks" / "eip7702_sandbox"
    result = evaluate_full_benchmark(corpus, corpus / "labels.json")

    assert result["overall"]["samples"] == 57
    assert result["overall"]["tp"] == 21
    assert result["overall"]["tn"] == 36
    assert result["overall"]["fp"] == 0
    assert result["overall"]["fn"] == 0
    assert result["overall"]["wrong_class"] == 0
    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["f1"] == 1.0
    assert result["overall"]["specificity"] == 1.0


def test_eip7702_validation_subset_keeps_sandbox_metadata_coverage():
    corpus = ROOT / "benchmarks" / "eip7702_sandbox"
    result = evaluate_validation_subset(corpus, corpus / "manifest.json")

    assert result["summary"]["samples"] == 21
    assert result["summary"]["true_positive"] == 9
    assert result["summary"]["true_negative"] == 12
    assert result["summary"]["false_positive"] == 0
    assert result["summary"]["false_negative"] == 0
    assert result["summary"]["wrong_class"] == 0
    assert result["metrics"]["sandbox_boundary_accuracy"] == 1.0
    assert result["metrics"]["pre_behavior_trace_coverage"] == 1.0
