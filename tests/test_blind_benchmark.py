"""Regression checks for the external/blind benchmark runner."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_blind_benchmark import evaluate  # noqa: E402


TX_ORIGIN_VULN = """
pragma solidity ^0.8.23;

contract Gate {
    function enter() external {
        require(tx.origin == msg.sender, "EOA only");
    }
}
"""


CLEAN_SAMPLE = """
pragma solidity ^0.8.23;

contract Clean {
    address public owner;
    function enter() external {
        require(msg.sender == owner, "owner");
    }
}
"""


ENTRYPOINT_UNLABELED = """
pragma solidity ^0.8.23;

struct PackedUserOperation { address sender; bytes signature; }

contract Account {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        returns (uint256)
    {
        require(userOpHash != bytes32(0), "context");
        return userOp.signature.length == 65 ? 0 : 1;
    }
}
"""


def _write_corpus(tmp_path: Path) -> tuple[Path, Path]:
    corpus = tmp_path / "external"
    (corpus / "positive").mkdir(parents=True)
    (corpus / "negative").mkdir()
    (corpus / "blind").mkdir()
    (corpus / "positive" / "TxOrigin.sol").write_text(TX_ORIGIN_VULN, encoding="utf-8")
    (corpus / "negative" / "Clean.sol").write_text(CLEAN_SAMPLE, encoding="utf-8")
    (corpus / "blind" / "EntryPoint.sol").write_text(ENTRYPOINT_UNLABELED, encoding="utf-8")

    manifest = {
        "name": "test_external_blind",
        "version": "0.1.0",
        "samples": [
            {
                "id": "known-positive-aa7702-001",
                "path": "positive/TxOrigin.sol",
                "label": "vulnerable",
                "expected_rule": "AA7702-001",
                "rule_under_test": "AA7702-001",
                "detector_under_test": "eip7702",
            },
            {
                "id": "known-negative-aa7702-001",
                "path": "negative/Clean.sol",
                "label": "benign",
                "expected_rule": None,
                "rule_under_test": "AA7702-001",
                "detector_under_test": "eip7702",
            },
            {
                "id": "blind-entrypoint-gate",
                "path": "blind/EntryPoint.sol",
                "rule_under_test": "AA7562-008",
                "detector_under_test": "eip7702_validation",
            },
        ],
    }
    manifest_path = corpus / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return corpus, manifest_path


def test_blind_benchmark_scores_labeled_samples_and_records_unlabeled(tmp_path):
    corpus, manifest = _write_corpus(tmp_path)

    result = evaluate(corpus, manifest)

    assert result["summary"]["samples"] == 3
    assert result["summary"]["labeled_samples"] == 2
    assert result["summary"]["true_positive"] == 1
    assert result["summary"]["true_negative"] == 1
    assert result["summary"]["false_positive"] == 0
    assert result["summary"]["false_negative"] == 0
    assert result["summary"]["unlabeled_detected"] == 1
    assert result["metrics"]["f1"] == 1.0
    assert result["manifest_contract"]["schema"] == "schemas/chainedr-blind-benchmark-manifest.schema.json"
    assert result["manifest_contract"]["samples_validated"] == 3
    assert result["per_rule_metrics"]["AA7702-001"]["precision"] == 1.0
    assert result["per_rule_metrics"]["AA7702-001"]["specificity"] == 1.0
    assert result["detected_rule_counts"]["AA7702-001"] == 1
    assert result["detected_rule_counts"]["AA7562-008"] == 1
    assert result["confusion_matrix"]["AA7702-001"]["AA7702-001"] == 1
    assert result["confusion_matrix"]["NEGATIVE:AA7702-001"]["NO_DETECTION"] == 1
    assert result["confusion_matrix"]["UNLABELED:AA7562-008"]["AA7562-008"] == 1
    assert result["label_inventory"]["raw_labels"]["vulnerable"] == 1
    assert result["label_inventory"]["raw_labels"]["benign"] == 1
    assert result["label_inventory"]["raw_labels"]["unlabeled"] == 1
    assert result["runtime"]["total_s"] >= 0
    assert result["runtime"]["p95_s"] >= 0

    blind = next(sample for sample in result["per_sample"] if sample["id"] == "blind-entrypoint-gate")
    assert blind["status"] == "UNLABELED_DETECTED"
    assert blind["triage_status"] == "needs_label_reveal"
    assert "independent labeling" in blind["triage_note"]
    assert blind["detected_rules"] == ["AA7562-008"]
    assert len(blind["content_sha256"]) == 64


def test_blind_benchmark_rejects_paths_outside_corpus(tmp_path):
    corpus, manifest = _write_corpus(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["samples"][0]["path"] = "../escape.sol"
    manifest.write_text(json.dumps(data), encoding="utf-8")

    try:
        evaluate(corpus, manifest)
    except ValueError as exc:
        assert "escapes corpus" in str(exc)
    else:
        raise AssertionError("expected path escape rejection")


def test_blind_benchmark_rejects_duplicate_sample_ids(tmp_path):
    corpus, manifest = _write_corpus(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["samples"][1]["id"] = data["samples"][0]["id"]
    manifest.write_text(json.dumps(data), encoding="utf-8")

    try:
        evaluate(corpus, manifest)
    except ValueError as exc:
        assert "duplicate sample id" in str(exc)
    else:
        raise AssertionError("expected duplicate id rejection")


def test_blind_benchmark_requires_explicit_detector(tmp_path):
    corpus, manifest = _write_corpus(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    del data["samples"][0]["detector_under_test"]
    manifest.write_text(json.dumps(data), encoding="utf-8")

    try:
        evaluate(corpus, manifest)
    except ValueError as exc:
        assert "unsupported detector_under_test" in str(exc)
    else:
        raise AssertionError("expected missing detector rejection")


def test_blind_benchmark_rejects_vulnerable_label_without_expected_rule(tmp_path):
    corpus, manifest = _write_corpus(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["samples"][0]["expected_rule"] = None
    manifest.write_text(json.dumps(data), encoding="utf-8")

    try:
        evaluate(corpus, manifest)
    except ValueError as exc:
        assert "vulnerable sample" in str(exc)
        assert "expected_rule" in str(exc)
    else:
        raise AssertionError("expected vulnerable label validation")


def test_blind_benchmark_rejects_negative_label_with_expected_rule(tmp_path):
    corpus, manifest = _write_corpus(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["samples"][1]["expected_rule"] = "AA7702-001"
    manifest.write_text(json.dumps(data), encoding="utf-8")

    try:
        evaluate(corpus, manifest)
    except ValueError as exc:
        assert "negative/control sample" in str(exc)
        assert "rule_under_test" in str(exc)
    else:
        raise AssertionError("expected negative control validation")
