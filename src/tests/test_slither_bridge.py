"""
Tests for ChainEDR Slither Bridge — Module 8.5

All tests use pre-computed Slither JSON — no Slither installation required,
no network, no filesystem writes.

Run with:
    pytest tests/test_slither_bridge.py -v
"""

import pytest
from unittest.mock import patch, MagicMock

from chainedr.slither_bridge import (
    SlitherBridge,
    SlitherRunner,
    SlitherParser,
    SlitherFinding,
    SlitherResult,
    CrossValidationResult,
    DETECTOR_TO_CHAINEDR,
    IMPACT_TO_SEVERITY,
    run_slither,
)
from chainedr.fp_filter import AuditContext


# ─── FIXTURE: minimal Slither JSON payloads ───────────────────────────────────

def _slither_json(detectors: list, success: bool = True) -> dict:
    return {
        "success": success,
        "error": None,
        "results": {"detectors": detectors},
    }


def _detector(
    check: str = "reentrancy-eth",
    impact: str = "High",
    confidence: str = "Medium",
    description: str = "Reentrancy in withdraw()",
    contract: str = "Vault",
    function: str = "withdraw",
    source_file: str = "Vault.sol",
    lines: list = None,
) -> dict:
    return {
        "check": check,
        "impact": impact,
        "confidence": confidence,
        "description": description,
        "elements": [
            {
                "type": "function",
                "name": function,
                "source_mapping": {
                    "filename_used": source_file,
                    "lines": lines or [42, 43, 44],
                },
                "type_specific_fields": {
                    "parent": {"type": "contract", "name": contract}
                },
            }
        ],
    }


def _mock_vuln(
    vuln_type: str = "REENTRANCY",
    function_sig: str = "withdraw(uint256)",
    confidence: float = 0.75,
):
    """Minimal mock of ClassifiedVulnerability for cross-validation tests."""
    alert = MagicMock()
    alert.function_sig = function_sig
    vuln = MagicMock()
    vuln.vulnerability_type = vuln_type
    vuln.confidence = confidence
    vuln.alert = alert
    return vuln


# ─── PARSER TESTS ────────────────────────────────────────────────────────────

class TestSlitherParser:
    def setup_method(self):
        self.parser = SlitherParser()

    def test_parse_empty_success(self):
        result = self.parser.parse(_slither_json([]))
        assert result.success is True
        assert result.findings == []

    def test_parse_single_reentrancy(self):
        j = _slither_json([_detector("reentrancy-eth", impact="High")])
        result = self.parser.parse(j)
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.detector_id == "reentrancy-eth"
        assert f.chainedr_type == "REENTRANCY"
        assert f.severity == "HIGH"
        assert f.is_reentrancy is True
        assert f.is_access_control is False

    def test_parse_access_control(self):
        j = _slither_json([_detector("arbitrary-send-eth", impact="High", confidence="High")])
        result = self.parser.parse(j)
        f = result.findings[0]
        assert f.chainedr_type == "ACCESS_CONTROL"
        assert f.confidence == 0.90  # "High" confidence → 0.90
        assert f.is_access_control is True

    def test_parse_unknown_detector_maps_to_unclassified(self):
        j = _slither_json([_detector("some-future-detector-v99")])
        result = self.parser.parse(j)
        assert result.findings[0].chainedr_type == "UNCLASSIFIED_ANOMALY"

    def test_parse_multiple_detectors(self):
        j = _slither_json([
            _detector("reentrancy-eth"),
            _detector("arbitrary-send-eth", impact="High"),
            _detector("integer-overflow", impact="Medium"),
            _detector("locked-ether", impact="Medium"),
        ])
        result = self.parser.parse(j)
        assert len(result.findings) == 4
        types = {f.chainedr_type for f in result.findings}
        assert "REENTRANCY" in types
        assert "ACCESS_CONTROL" in types
        assert "INTEGER_OVERFLOW" in types
        assert "UNCLASSIFIED_ANOMALY" in types

    def test_parse_extracts_location(self):
        j = _slither_json([_detector(
            contract="StreamableFeesLockerV2",
            function="lock",
            source_file="StreamableFeesLockerV2.sol",
            lines=[100, 101, 102],
        )])
        result = self.parser.parse(j)
        f = result.findings[0]
        assert f.contract_name == "StreamableFeesLockerV2"
        assert f.function_name == "lock"
        assert f.source_file == "StreamableFeesLockerV2.sol"
        assert f.source_lines == [100, 101, 102]
        assert f.location == "StreamableFeesLockerV2.lock()"

    def test_parse_failure_json(self):
        j = {"success": False, "error": "Compilation failed", "results": {}}
        result = self.parser.parse(j)
        assert result.success is False
        assert "Compilation" in result.error

    def test_impact_severity_mapping(self):
        for impact, expected in [
            ("High", "HIGH"), ("Medium", "MEDIUM"), ("Low", "LOW"), ("Informational", "LOW")
        ]:
            j = _slither_json([_detector(impact=impact)])
            result = self.parser.parse(j)
            assert result.findings[0].severity == expected

    def test_confidence_mapping(self):
        for confidence_str, expected in [
            ("High", 0.90), ("Medium", 0.65), ("Low", 0.40)
        ]:
            j = _slither_json([_detector(confidence=confidence_str)])
            result = self.parser.parse(j)
            assert result.findings[0].confidence == expected


# ─── SLITHER RESULT PROPERTIES ───────────────────────────────────────────────

class TestSlitherResult:
    def _make_result(self, checks: list) -> SlitherResult:
        parser = SlitherParser()
        return parser.parse(_slither_json([_detector(c) for c in checks]))

    def test_reentrancy_count(self):
        r = self._make_result(["reentrancy-eth", "reentrancy-no-eth", "arbitrary-send-eth"])
        assert r.reentrancy_count == 2

    def test_access_control_count(self):
        r = self._make_result(["arbitrary-send-eth", "controlled-delegatecall", "reentrancy-eth"])
        assert r.access_control_count == 2

    def test_by_type(self):
        r = self._make_result(["reentrancy-eth", "arbitrary-send-eth"])
        bt = r.by_type
        assert "REENTRANCY" in bt
        assert "ACCESS_CONTROL" in bt

    def test_summary_includes_access_control_note(self):
        r = self._make_result(["arbitrary-send-eth"])
        s = r.summary()
        assert "ChainEDR blind spot" in s

    def test_summary_failure(self):
        r = SlitherResult(success=False, error="not found")
        assert "not found" in r.summary()

    def test_empty_findings_summary(self):
        r = SlitherResult(success=True)
        assert "No findings" in r.summary()


# ─── BRIDGE: run() with pre-computed JSON ────────────────────────────────────

class TestSlitherBridgeRun:
    def setup_method(self):
        self.bridge = SlitherBridge()

    def test_run_with_json(self):
        j = _slither_json([_detector("reentrancy-eth")])
        result = self.bridge.run(slither_json=j)
        assert result.success is True
        assert len(result.findings) == 1

    def test_run_no_source_returns_error(self):
        result = self.bridge.run()
        assert result.success is False

    def test_run_with_json_empty(self):
        result = self.bridge.run(slither_json=_slither_json([]))
        assert result.findings == []


# ─── CROSS-VALIDATION ─────────────────────────────────────────────────────────

class TestCrossValidation:
    def setup_method(self):
        self.bridge = SlitherBridge()
        self.parser = SlitherParser()

    def _findings(self, checks: list, function: str = "withdraw") -> list:
        j = _slither_json([_detector(c, function=function) for c in checks])
        return self.parser.parse(j).findings

    def test_corroboration_same_type_same_function(self):
        chainedr = [_mock_vuln("REENTRANCY", "withdraw(uint256)", confidence=0.75)]
        slither = self._findings(["reentrancy-eth"], function="withdraw")
        xval = self.bridge.cross_validate(chainedr, slither)
        assert len(xval.corroborated) == 1
        assert len(xval.slither_only) == 0
        assert len(xval.chainedr_only) == 0

    def test_confidence_boosted_on_corroboration(self):
        vuln = _mock_vuln("REENTRANCY", "withdraw(uint256)", confidence=0.75)
        slither = self._findings(["reentrancy-eth"], function="withdraw")
        self.bridge.cross_validate([vuln], slither)
        assert vuln.confidence == pytest.approx(0.75 + 0.15, abs=0.01)

    def test_confidence_capped_at_1(self):
        vuln = _mock_vuln("REENTRANCY", "withdraw(uint256)", confidence=0.95)
        slither = self._findings(["reentrancy-eth"], function="withdraw")
        self.bridge.cross_validate([vuln], slither)
        assert vuln.confidence <= 1.0

    def test_slither_only_access_control(self):
        """Slither finds ACCESS_CONTROL, ChainEDR found nothing → slither_only."""
        chainedr = [_mock_vuln("REENTRANCY", "withdraw(uint256)")]
        slither = self._findings(["arbitrary-send-eth"], function="setAdmin")
        xval = self.bridge.cross_validate(chainedr, slither)
        assert len(xval.slither_only) == 1
        assert xval.slither_only[0].chainedr_type == "ACCESS_CONTROL"

    def test_chainedr_only_flash_loan(self):
        """ChainEDR detects FLASH_LOAN, Slither doesn't → chainedr_only."""
        vuln = _mock_vuln("FLASH_LOAN_ATTACK", "swap(uint256)")
        slither = self._findings(["reentrancy-eth"], function="withdraw")
        xval = self.bridge.cross_validate([vuln], slither)
        assert len(xval.chainedr_only) == 1

    def test_empty_chainedr(self):
        slither = self._findings(["arbitrary-send-eth"])
        xval = self.bridge.cross_validate([], slither)
        assert len(xval.slither_only) == 1
        assert len(xval.corroborated) == 0

    def test_empty_slither(self):
        vuln = _mock_vuln("REENTRANCY")
        xval = self.bridge.cross_validate([vuln], [])
        assert len(xval.chainedr_only) == 1
        assert len(xval.corroborated) == 0

    def test_cross_val_summary_format(self):
        vuln = _mock_vuln("REENTRANCY", "withdraw(uint256)")
        slither = self._findings(["reentrancy-eth", "arbitrary-send-eth"])
        xval = self.bridge.cross_validate([vuln], slither)
        s = xval.summary()
        assert "Corroborated" in s
        assert "Slither only" in s


# ─── AUDIT CONTEXT ENRICHMENT ─────────────────────────────────────────────────

class TestAuditContextEnrichment:
    def setup_method(self):
        self.bridge = SlitherBridge()
        self.parser = SlitherParser()

    def _ctx(self, **kwargs) -> AuditContext:
        defaults = dict(
            solidity_version="0.8.19",
            function_modifiers=[],
            has_rescue_function=True,
        )
        defaults.update(kwargs)
        return AuditContext(**defaults)

    def _result_from_check(self, check: str, function: str = "withdraw") -> SlitherResult:
        j = _slither_json([_detector(check, function=function)])
        return self.parser.parse(j)

    def test_locked_ether_sets_rescue_false(self):
        ctx = self._ctx(has_rescue_function=True)
        result = self._result_from_check("locked-ether")
        enriched = self.bridge.enrich_audit_context(ctx, result)
        assert enriched.has_rescue_function is False

    def test_arbitrary_send_removes_privileged_modifiers(self):
        ctx = self._ctx(
            function_modifiers=["onlyOwner", "nonReentrant"],
        )
        result = self._result_from_check("arbitrary-send-eth", function="withdraw")
        enriched = self.bridge.enrich_audit_context(ctx, result, function_sig="withdraw()")
        assert "onlyOwner" not in enriched.function_modifiers
        # nonReentrant should survive (not a privileged modifier)
        assert "nonReentrant" in enriched.function_modifiers

    def test_reentrancy_benign_adds_nonreentrant(self):
        ctx = self._ctx(function_modifiers=[])
        result = self._result_from_check("reentrancy-benign")
        enriched = self.bridge.enrich_audit_context(ctx, result)
        assert "nonReentrant" in enriched.function_modifiers

    def test_no_mutation_for_unrelated_detectors(self):
        ctx = self._ctx(has_rescue_function=True, function_modifiers=["onlyOwner"])
        result = self._result_from_check("integer-overflow")
        enriched = self.bridge.enrich_audit_context(ctx, result)
        assert enriched.has_rescue_function is True
        assert "onlyOwner" in enriched.function_modifiers


# ─── REPORT SECTION RENDERING ────────────────────────────────────────────────

class TestReportSectionRendering:
    def setup_method(self):
        self.bridge = SlitherBridge()
        self.parser = SlitherParser()

    def test_render_with_findings(self):
        j = _slither_json([
            _detector("reentrancy-eth", impact="High"),
            _detector("arbitrary-send-eth", impact="High"),
        ])
        result = self.parser.parse(j)
        section = self.bridge.findings_to_report_section(result)
        assert "reentrancy-eth" in section
        assert "arbitrary-send-eth" in section
        assert "corroborating evidence" in section.lower()

    def test_render_no_findings(self):
        result = SlitherResult(success=True)
        section = self.bridge.findings_to_report_section(result)
        assert "No findings" in section or "clean" in section.lower()

    def test_render_failure(self):
        result = SlitherResult(success=False, error="slither not found")
        section = self.bridge.findings_to_report_section(result)
        assert "Not available" in section or "slither not found" in section

    def test_render_sorted_by_severity(self):
        j = _slither_json([
            _detector("weak-prng", impact="Low"),
            _detector("reentrancy-eth", impact="High"),
            _detector("integer-overflow", impact="Medium"),
        ])
        result = self.parser.parse(j)
        section = self.bridge.findings_to_report_section(result)
        high_pos = section.find("HIGH")
        medium_pos = section.find("MEDIUM")
        low_pos = section.find("LOW")
        assert high_pos < medium_pos < low_pos


# ─── RUNNER AVAILABILITY CHECK ───────────────────────────────────────────────

class TestSlitherRunner:
    def test_is_available_returns_bool(self):
        runner = SlitherRunner()
        result = runner.is_available()
        assert isinstance(result, bool)

    def test_run_on_file_no_slither(self):
        """When slither is not installed, should return error dict gracefully."""
        runner = SlitherRunner()
        with patch("shutil.which", return_value=None):
            result = runner.run_on_file("Contract.sol")
        assert result["success"] is False
        assert "slither not found" in result["error"].lower()


# ─── DETECTOR MAPPING COMPLETENESS ───────────────────────────────────────────

class TestDetectorMapping:
    def test_all_mapped_types_are_valid_chainedr_types(self):
        valid = {
            "REENTRANCY", "ACCESS_CONTROL", "FLASH_LOAN_ATTACK",
            "ORACLE_MANIPULATION", "INTEGER_OVERFLOW", "UNCHECKED_RETURN",
            "UNCLASSIFIED_ANOMALY",
        }
        for detector, chainedr_type in DETECTOR_TO_CHAINEDR.items():
            assert chainedr_type in valid, (
                f"Detector {detector!r} maps to unknown type {chainedr_type!r}"
            )

    def test_access_control_detectors_mapped(self):
        assert DETECTOR_TO_CHAINEDR["arbitrary-send-eth"] == "ACCESS_CONTROL"
        assert DETECTOR_TO_CHAINEDR["controlled-delegatecall"] == "ACCESS_CONTROL"
        assert DETECTOR_TO_CHAINEDR["suicidal"] == "ACCESS_CONTROL"

    def test_reentrancy_detectors_mapped(self):
        assert DETECTOR_TO_CHAINEDR["reentrancy-eth"] == "REENTRANCY"
        assert DETECTOR_TO_CHAINEDR["reentrancy-no-eth"] == "REENTRANCY"
        assert DETECTOR_TO_CHAINEDR["delegatecall-loop"] == "REENTRANCY"


# ─── CONVENIENCE FUNCTION ─────────────────────────────────────────────────────

class TestRunSlitherConvenience:
    def test_run_slither_with_json(self):
        j = _slither_json([_detector("reentrancy-eth")])
        result = run_slither(slither_json=j)
        assert isinstance(result, SlitherResult)
        assert len(result.findings) == 1

    def test_run_slither_no_args(self):
        result = run_slither()
        assert result.success is False
