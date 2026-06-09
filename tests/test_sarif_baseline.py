"""
Tests for SARIF fingerprints + suppression metadata and the CI baseline diff.

Covers:
  - finding_fingerprint is stable across line drift / path differences and
    distinguishes genuinely different findings.
  - SARIF results carry partialFingerprints; advisories / triaged FPs carry a
    SARIF `suppressions` entry.
  - Baseline diff: a finding whose fingerprint is in the baseline is "known".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sarif_output import finding_fingerprint, to_sarif_v2_1_0  # noqa: E402


def _f(**kw):
    base = {"check": "raw_ecrecover", "file": "src/A.sol", "function": "verify",
            "line": 42, "severity": "MEDIUM", "description": "raw ecrecover at L42"}
    base.update(kw)
    return base


def test_fingerprint_stable_across_line_and_path():
    a = _f(line=42, file="src/A.sol", description="raw ecrecover at L42")
    b = _f(line=99, file="/abs/ci/checkout/src/A.sol", description="raw ecrecover at L99")
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_differs_by_check_and_function():
    a = _f(function="verify")
    b = _f(function="validate")
    c = _f(check="silent_truncation")
    assert finding_fingerprint(a) != finding_fingerprint(b)
    assert finding_fingerprint(a) != finding_fingerprint(c)


def test_sarif_has_partial_fingerprints():
    sarif = to_sarif_v2_1_0([_f()], tool_version="3.0.0")
    res = sarif["runs"][0]["results"][0]
    assert "partialFingerprints" in res
    assert res["partialFingerprints"]["chainedrFingerprint/v1"] == finding_fingerprint(_f())


def test_sarif_suppresses_advisory():
    adv = _f(check="permit_frontrun_advisory", advisory=True, severity="INFORMATIONAL")
    res = to_sarif_v2_1_0([adv])["runs"][0]["results"][0]
    assert "suppressions" in res and res["suppressions"][0]["kind"] == "inSource"


def test_sarif_suppresses_triaged_fp():
    fp = _f(fp_analysis={"verdict": "FALSE_POSITIVE", "reason": "interface stub"})
    res = to_sarif_v2_1_0([fp])["runs"][0]["results"][0]
    assert "suppressions" in res
    assert "interface" in res["suppressions"][0]["justification"]


def test_sarif_real_finding_not_suppressed():
    res = to_sarif_v2_1_0([_f()])["runs"][0]["results"][0]
    assert "suppressions" not in res


def test_baseline_diff_marks_known_finding():
    findings = [_f(function="verify"), _f(function="other")]
    baseline = {finding_fingerprint(findings[0])}
    new = [f for f in findings if finding_fingerprint(f) not in baseline]
    assert len(new) == 1 and new[0]["function"] == "other"
