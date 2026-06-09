"""
EIP7702-Bench corpus evaluation test.

Runs the full 47-contract benchmark corpus and verifies:
- All 21 vulnerable contracts trigger their expected check
- All 21 fixed contracts do NOT trigger their expected check
- All 5 benign contracts produce 0 EIP-7702 findings
"""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from eip7702_detector import EIP7702Detector

CORPUS_DIR = os.path.join(os.path.dirname(__file__), '..', 'benchmarks', 'eip7702_full')
LABELS_PATH = os.path.join(CORPUS_DIR, 'labels.json')


@pytest.fixture(scope="module")
def detector():
    return EIP7702Detector()


@pytest.fixture(scope="module")
def labels():
    with open(LABELS_PATH) as f:
        return json.load(f)


class TestVulnerableContracts:
    """Each vulnerable contract must trigger its expected check."""

    @pytest.fixture(autouse=True)
    def _setup(self, detector, labels):
        self.detector = detector
        self.labels = {k: v for k, v in labels.items() if v['category'] == 'vulnerable'}

    def test_all_21_vulnerable_detected(self):
        missed = []
        for rel_path, label in sorted(self.labels.items()):
            abs_path = os.path.join(CORPUS_DIR, rel_path)
            source = open(abs_path).read()
            findings = self.detector.check(source)
            found_ids = {f.check_id for f in findings}
            for eid in label['expected_findings']:
                if eid not in found_ids:
                    missed.append(f"{rel_path}: expected {eid}, found {sorted(found_ids)}")
        assert not missed, f"Missed detections:\n" + "\n".join(missed)

    def test_count_is_21(self):
        assert len(self.labels) == 21


class TestFixedContracts:
    """Each fixed contract must NOT trigger its expected check."""

    @pytest.fixture(autouse=True)
    def _setup(self, detector, labels):
        self.detector = detector
        self.labels = {k: v for k, v in labels.items() if v['category'] == 'fixed'}

    def test_all_21_fixed_clean(self):
        fps = []
        for rel_path, label in sorted(self.labels.items()):
            abs_path = os.path.join(CORPUS_DIR, rel_path)
            source = open(abs_path).read()
            findings = self.detector.check(source)
            found_ids = {f.check_id for f in findings}
            for mid in label.get('must_not_detect', []):
                if mid in found_ids:
                    fps.append(f"{rel_path}: false positive {mid}")
        assert not fps, f"False positives:\n" + "\n".join(fps)

    def test_count_is_21(self):
        assert len(self.labels) == 21


class TestBenignContracts:
    """Benign contracts must produce 0 EIP-7702 findings."""

    @pytest.fixture(autouse=True)
    def _setup(self, detector, labels):
        self.detector = detector
        self.labels = {k: v for k, v in labels.items() if v['category'] == 'benign'}

    def test_all_benign_zero_findings(self):
        fps = []
        for rel_path, label in sorted(self.labels.items()):
            abs_path = os.path.join(CORPUS_DIR, rel_path)
            source = open(abs_path).read()
            findings = self.detector.check(source)
            if findings:
                ids = sorted(set(f.check_id for f in findings))
                fps.append(f"{rel_path}: found {ids}")
        assert not fps, f"Benign false positives:\n" + "\n".join(fps)

    def test_count_is_5(self):
        assert len(self.labels) == 5


class TestCorpusMetrics:
    """Overall metrics must meet thresholds."""

    def test_precision_recall_f1(self, detector, labels):
        tp, fp, fn = 0, 0, 0
        for rel_path, label in labels.items():
            abs_path = os.path.join(CORPUS_DIR, rel_path)
            source = open(abs_path).read()
            findings = detector.check(source)
            found_ids = {f.check_id for f in findings}

            if label['category'] == 'vulnerable':
                for eid in label['expected_findings']:
                    if eid in found_ids:
                        tp += 1
                    else:
                        fn += 1
            elif label['category'] == 'fixed':
                for mid in label.get('must_not_detect', []):
                    if mid in found_ids:
                        fp += 1
            elif label['category'] == 'benign':
                if findings:
                    fp += len(set(f.check_id for f in findings))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        assert recall >= 0.95, f"Recall too low: {recall:.4f}"
        assert precision >= 0.90, f"Precision too low: {precision:.4f}"
        assert f1 >= 0.95, f"F1 too low: {f1:.4f}"
