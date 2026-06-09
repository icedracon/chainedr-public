"""
chainedr/tests/test_erc4337_invariants.py — Session 5 deterministic tests (RULE-03)

Acceptance criteria:
  PASS: tracer detects SELFDESTRUCT in validateUserOp frame
  PASS: tracer does NOT flag SELFDESTRUCT in execution frame
  PASS: gas_grief template compiles
  FAIL: tracer uses string grep (must parse JSON structurally)
  FAIL: invariants use Echidna for opcode checks (wrong tool)
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INVARIANTS = PROJECT_ROOT / "invariants" / "erc4337.json"


class TestERC4337Invariants:
    @pytest.fixture(autouse=True)
    def load(self):
        with open(INVARIANTS, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def test_eip_4337(self):
        assert self.data["eip"] == "EIP-4337"

    def test_five_invariants(self):
        assert len(self.data["invariants"]) == 5

    def test_required_fields(self):
        for inv in self.data["invariants"]:
            assert "id" in inv and "eip_ref" in inv and "severity" in inv

    def test_no_echidna_for_opcode_checks(self):
        """CRITIC: Opcode checks must use tracer, NOT Echidna (RULE-10)."""
        opcode_invs = [i for i in self.data["invariants"] if i["type"] == "OPCODE_VIOLATION"]
        for inv in opcode_invs:
            assert inv.get("echidna_compatible") is False, (
                f"{inv['id']}: OPCODE_VIOLATION must not use Echidna (RULE-10)"
            )
            assert inv.get("tool") == "tracer"

    def test_forbidden_opcodes_listed(self):
        inv01 = next(i for i in self.data["invariants"] if i["id"] == "INV-4337-01")
        forbidden = inv01.get("forbidden_opcodes", [])
        assert "SELFDESTRUCT" in forbidden
        assert "CREATE" in forbidden
        assert "BASEFEE" in forbidden

    def test_storage_restriction_deferred(self):
        """CRITIC: INV-4337-04 storage restriction deferred — must be documented."""
        inv04 = next(i for i in self.data["invariants"] if i["id"] == "INV-4337-04")
        lims = inv04.get("known_limitations", [])
        assert any("defer" in l.lower() or "storage slot" in l.lower() for l in lims)


class TestOpcodeTracer:
    def test_import(self):
        from chainedr.tracer.erc4337_opcode_check import parse_trace, check_forbidden_opcodes
        assert callable(parse_trace)

    def test_detects_selfdestruct_in_validation(self):
        """PASS: tracer detects SELFDESTRUCT in validateUserOp frame."""
        from chainedr.tracer.erc4337_opcode_check import parse_trace

        trace = {
            "type": "CALL",
            "from": "0xentrypoint",
            "to": "0xaccount",
            "input": "0x3a871cdd" + "00" * 64,  # validateUserOp selector
            "gasUsed": "0x5000",
            "calls": [
                {
                    "type": "SELFDESTRUCT",
                    "from": "0xaccount",
                    "to": "0x0",
                    "input": "0x",
                    "gasUsed": "0x100",
                }
            ],
        }
        analysis = parse_trace(trace)
        assert analysis.has_violations
        assert analysis.violations[0].opcode == "SELFDESTRUCT"
        assert analysis.violations[0].frame_type == "validation"

    def test_does_not_flag_selfdestruct_in_execution(self):
        """PASS: tracer does NOT flag SELFDESTRUCT in execution frame."""
        from chainedr.tracer.erc4337_opcode_check import parse_trace

        trace = {
            "type": "CALL",
            "from": "0xentrypoint",
            "to": "0xaccount",
            "input": "0xabcdef00" + "00" * 64,  # NOT validateUserOp
            "gasUsed": "0x5000",
            "calls": [
                {
                    "type": "SELFDESTRUCT",
                    "from": "0xaccount",
                    "to": "0x0",
                    "input": "0x",
                    "gasUsed": "0x100",
                }
            ],
        }
        analysis = parse_trace(trace)
        assert not analysis.has_violations, (
            "SELFDESTRUCT in execution frame must NOT be flagged"
        )

    def test_detects_create_in_validation(self):
        from chainedr.tracer.erc4337_opcode_check import parse_trace

        trace = {
            "type": "CALL",
            "from": "0xentrypoint",
            "to": "0xaccount",
            "input": "0x3a871cdd" + "00" * 64,
            "gasUsed": "0x5000",
            "calls": [
                {
                    "type": "CREATE",
                    "from": "0xaccount",
                    "to": "0xnew",
                    "input": "0x",
                    "gasUsed": "0x200",
                }
            ],
        }
        analysis = parse_trace(trace)
        assert analysis.has_violations
        assert analysis.violations[0].opcode == "CREATE"

    def test_clean_validation_no_violations(self):
        from chainedr.tracer.erc4337_opcode_check import parse_trace

        trace = {
            "type": "CALL",
            "from": "0xentrypoint",
            "to": "0xaccount",
            "input": "0x3a871cdd" + "00" * 64,
            "gasUsed": "0x5000",
            "calls": [
                {
                    "type": "STATICCALL",
                    "from": "0xaccount",
                    "to": "0xsignature_check",
                    "input": "0x",
                    "gasUsed": "0x100",
                }
            ],
        }
        analysis = parse_trace(trace)
        assert not analysis.has_violations

    def test_parses_json_not_string_grep(self):
        """CRITIC: Must parse JSON structurally."""
        from chainedr.tracer import erc4337_opcode_check as mod
        import inspect
        src = inspect.getsource(mod.parse_trace)
        # Should use dict access, not regex/grep
        assert "isinstance" in src or ".get(" in src

    def test_findings_format(self):
        """Findings must match findings.json schema."""
        from chainedr.tracer.erc4337_opcode_check import check_forbidden_opcodes

        trace = {
            "type": "CALL",
            "from": "0xentrypoint",
            "to": "0xaccount",
            "input": "0x3a871cdd" + "00" * 64,
            "gasUsed": "0x5000",
            "calls": [
                {"type": "SELFDESTRUCT", "from": "0xaccount", "to": "0x0",
                 "input": "0x", "gasUsed": "0x100"}
            ],
        }
        findings = check_forbidden_opcodes(trace)
        assert len(findings) >= 1
        f = findings[0]
        assert "id" in f
        assert "type" in f and f["type"] == "OPCODE_VIOLATION"
        assert "severity" in f
        assert "eip_ref" in f
        assert "detail" in f

    def test_validation_frame_tracked(self):
        from chainedr.tracer.erc4337_opcode_check import parse_trace

        trace = {
            "type": "CALL", "from": "0x1", "to": "0x2",
            "input": "0x3a871cdd" + "00" * 64,
            "gasUsed": "0x1000", "calls": [],
        }
        analysis = parse_trace(trace)
        assert analysis.validation_frame_found


class TestRegressionS1toS4:
    def test_all_invariants_exist(self):
        for erc in ["erc20", "erc721", "erc4626", "erc1155", "erc4337"]:
            assert (PROJECT_ROOT / "invariants" / f"{erc}.json").exists()
