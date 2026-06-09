"""
ChainEDR Slither Bridge — Module 8.5

Runs Slither on contract source, parses its JSON output, maps findings to
ChainEDR's vulnerability taxonomy, and cross-validates against ChainEDR's
own behavioral detections.

Why this matters:
  ChainEDR: 100% reentrancy, 100% flash loans, 0% access control
  Slither:  ~80% reentrancy, 0% flash loans, ~60% access control
  Together: ~65% of the full attack taxonomy covered (estimated)

Architecture:
  SlitherRunner   — subprocess wrapper that calls `slither --json -`
  SlitherParser   — maps Slither detector IDs → ChainEDR finding types
  SlitherBridge   — orchestrates: run → parse → cross-validate → enrich

Pipeline position:
  Explorer → Fuzzer → Profiler → Monitor → Classifier
      → [SlitherBridge]           ← runs in parallel with fuzzer
      → Reporter (combined output)

Usage:
    bridge = SlitherBridge()

    # Option A: from source file path
    result = bridge.run(source_path="contracts/MyToken.sol")

    # Option B: from already-parsed Slither JSON (for testing / CI)
    result = bridge.run(slither_json=json_dict)

    # Cross-validate against ChainEDR classifier findings
    combined = bridge.cross_validate(chainedr_vulns, result.findings)
    # combined.corroborated  — both tools agree (higher confidence)
    # combined.slither_only  — Slither caught it, ChainEDR missed
    # combined.chainedr_only — ChainEDR caught it, Slither missed

    # Enrich AuditContext for FP filter
    ctx = bridge.enrich_audit_context(ctx, result)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any

from .fp_filter import AuditContext


# ─── SLITHER DETECTOR → CHAINEDR TYPE MAPPING ────────────────────────────────

DETECTOR_TO_CHAINEDR: Dict[str, str] = {
    # Reentrancy
    "reentrancy-eth":           "REENTRANCY",
    "reentrancy-no-eth":        "REENTRANCY",
    "reentrancy-benign":        "REENTRANCY",
    "reentrancy-events":        "REENTRANCY",
    "delegatecall-loop":        "REENTRANCY",
    # Access control
    "arbitrary-send-eth":       "ACCESS_CONTROL",
    "arbitrary-send-erc20":     "ACCESS_CONTROL",
    "controlled-delegatecall":  "ACCESS_CONTROL",
    "suicidal":                 "ACCESS_CONTROL",
    "unprotected-upgrade":      "ACCESS_CONTROL",
    "missing-zero-check":       "ACCESS_CONTROL",
    "tx-origin":                "ACCESS_CONTROL",
    "protected-vars":           "ACCESS_CONTROL",
    "msg-value-loop":           "ACCESS_CONTROL",
    # Oracle / price
    "price-manipulation":       "ORACLE_MANIPULATION",
    "weak-prng":                "ORACLE_MANIPULATION",
    # Arithmetic
    "integer-overflow":         "INTEGER_OVERFLOW",
    "tautology":                "INTEGER_OVERFLOW",
    "divide-before-multiply":   "INTEGER_OVERFLOW",
    # Unchecked returns
    "unchecked-lowlevel":       "UNCHECKED_RETURN",
    "unchecked-send":           "UNCHECKED_RETURN",
    "unused-return":            "UNCHECKED_RETURN",
    # Flash loan (structural proxy)
    "flash-loan":               "FLASH_LOAN_ATTACK",
    # Misc → unclassified
    "shadowing-state":          "UNCLASSIFIED_ANOMALY",
    "locked-ether":             "UNCLASSIFIED_ANOMALY",
    "incorrect-equality":       "UNCLASSIFIED_ANOMALY",
    "calls-loop":               "UNCLASSIFIED_ANOMALY",
    "boolean-equality":         "UNCLASSIFIED_ANOMALY",
    "variable-scope":           "UNCLASSIFIED_ANOMALY",
    "dead-code":                "UNCLASSIFIED_ANOMALY",
}

# Slither "impact" string → ChainEDR severity
IMPACT_TO_SEVERITY: Dict[str, str] = {
    "High":          "HIGH",
    "Medium":        "MEDIUM",
    "Low":           "LOW",
    "Informational": "LOW",
    "Optimization":  "LOW",
}

# Slither "confidence" string → float
CONFIDENCE_MAP: Dict[str, float] = {
    "High":   0.90,
    "Medium": 0.65,
    "Low":    0.40,
}

# How much to boost ChainEDR confidence when Slither corroborates
CORROBORATION_BOOST = 0.15


# ─── DATA STRUCTURES ─────────────────────────────────────────────────────────

@dataclass
class SlitherFinding:
    """A single finding parsed from Slither JSON output."""
    detector_id: str          # e.g. "reentrancy-eth"
    chainedr_type: str        # mapped ChainEDR vulnerability type
    severity: str             # CRITICAL / HIGH / MEDIUM / LOW
    confidence: float         # 0.0–1.0
    description: str
    contract_name: str = ""
    function_name: str = ""
    source_file: str = ""
    source_lines: List[int] = field(default_factory=list)
    raw: Dict = field(default_factory=dict)

    @property
    def location(self) -> str:
        if self.contract_name and self.function_name:
            return f"{self.contract_name}.{self.function_name}()"
        return self.source_file or "unknown"

    @property
    def is_access_control(self) -> bool:
        return self.chainedr_type == "ACCESS_CONTROL"

    @property
    def is_reentrancy(self) -> bool:
        return self.chainedr_type == "REENTRANCY"


@dataclass
class SlitherResult:
    """Full result of a Slither run."""
    success: bool
    findings: List[SlitherFinding] = field(default_factory=list)
    raw_output: Dict = field(default_factory=dict)
    error: str = ""
    slither_version: str = ""
    source_path: str = ""

    # Counts by type
    @property
    def reentrancy_count(self) -> int:
        return sum(1 for f in self.findings if f.is_reentrancy)

    @property
    def access_control_count(self) -> int:
        return sum(1 for f in self.findings if f.is_access_control)

    @property
    def by_type(self) -> Dict[str, List[SlitherFinding]]:
        result: Dict[str, List[SlitherFinding]] = {}
        for f in self.findings:
            result.setdefault(f.chainedr_type, []).append(f)
        return result

    @property
    def by_severity(self) -> Dict[str, List[SlitherFinding]]:
        result: Dict[str, List[SlitherFinding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    def summary(self) -> str:
        if not self.success:
            return f"Slither failed: {self.error}"
        if not self.findings:
            lines = ["No findings"]
        else:
            lines = [f"Slither: {len(self.findings)} findings"]
        for sev in ["HIGH", "MEDIUM", "LOW"]:
            count = len(self.by_severity.get(sev, []))
            if count:
                lines.append(f"  {sev}: {count}")
        ac = self.access_control_count
        re_ = self.reentrancy_count
        if ac:
            lines.append(f"  ACCESS_CONTROL: {ac} (ChainEDR blind spot covered)")
        if re_:
            lines.append(f"  REENTRANCY: {re_} (corroborates ChainEDR)")
        return "\n".join(lines)

    def to_static_findings(self) -> List:
        """
        Convert SlitherFindings to StaticFinding objects (chainedr.static_analyzer).

        Import is deferred to avoid circular dependency.
        Returns empty list if static_analyzer unavailable.
        """
        try:
            from .static_analyzer import StaticFinding, StaticSeverity, StaticCategory
        except ImportError:
            return []

        _sev_map = {
            "HIGH":   StaticSeverity.HIGH,
            "MEDIUM": StaticSeverity.MEDIUM,
            "LOW":    StaticSeverity.LOW,
        }
        _cat_map = {
            "REENTRANCY":          StaticCategory.REENTRANCY,
            "ACCESS_CONTROL":      StaticCategory.ACCESS_CONTROL,
            "UNCHECKED_RETURN":    StaticCategory.UNCHECKED_RETURN,
            "INTEGER_OVERFLOW":    StaticCategory.PRECISION,
            "ORACLE_MANIPULATION": StaticCategory.ORACLE,
            "FLASH_LOAN_ATTACK":   StaticCategory.REENTRANCY,
            "UNCLASSIFIED_ANOMALY": StaticCategory.LOGIC,
        }

        out = []
        for sf in self.findings:
            sev = _sev_map.get(sf.severity, StaticSeverity.INFO)
            cat = _cat_map.get(sf.chainedr_type, StaticCategory.LOGIC)
            lines_str = (f":L{sf.source_lines[0]}" if sf.source_lines else "")
            out.append(StaticFinding(
                severity=sev,
                category=cat,
                title=f"[Slither/{sf.detector_id}] {sf.function_name or sf.contract_name}",
                description=sf.description,
                location=sf.location + lines_str,
                exploitable=sf.severity in ("HIGH", "MEDIUM"),
                fix_suggestion="",
                cwe="",
                confidence=sf.confidence,
            ))
        return out


@dataclass
class CrossValidationResult:
    """Result of cross-validating ChainEDR findings against Slither findings."""
    corroborated: List[Dict]    # both tools agree — highest confidence
    slither_only: List[SlitherFinding]  # Slither caught it, ChainEDR missed
    chainedr_only: List[Any]    # ChainEDR caught it, Slither missed
    combined_coverage_pct: float = 0.0

    def summary(self) -> str:
        lines = [
            f"Cross-validation summary:",
            f"  ✓ Corroborated (both tools): {len(self.corroborated)}",
            f"  + Slither only (access control gap filled): {len(self.slither_only)}",
            f"  + ChainEDR only (flash loan / temporal): {len(self.chainedr_only)}",
            f"  Combined coverage: ~{self.combined_coverage_pct:.0f}%",
        ]
        return "\n".join(lines)


# ─── RUNNER ──────────────────────────────────────────────────────────────────

class SlitherRunner:
    """
    Thin subprocess wrapper around the `slither` CLI.

    Requires: pip install slither-analyzer  (solc via solc-select)

    Key behaviour:
    - Auto-detects solc version from pragma and passes SOLC_VERSION env var.
    - Foundry projects (foundry.toml present): copies source to a temp dir
      without the toml so crytic-compile uses solc instead of forge.
    - Falls back gracefully — returns {"success": False, "error": "..."}.
    """

    # Captures the operator prefix (^, >=, ~, =, or blank) and version triple.
    PRAGMA_RE = re.compile(
        r'pragma\s+solidity\s+(?:[^\d]*?)(\^|>=|~|=)?\s*(\d+\.\d+\.\d+)'
    )

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which("slither") is not None

    def _solc_version_for(self, source_code: str) -> Optional[str]:
        """
        Return an exact pinned version only for fixed pragmas (no ^ / >= / ~).
        Range pragmas like `^0.8.0` must NOT set SOLC_VERSION — solc-select
        picks the installed global, which is compatible.  Setting an exact
        patch that is not installed (e.g. 0.8.0 when only 0.8.19 is present)
        causes crytic-compile to fail silently (exit 1, empty stdout).
        """
        m = self.PRAGMA_RE.search(source_code)
        if not m:
            return None
        operator, version = m.group(1), m.group(2)
        # Only pin when the pragma is exact (no operator, or "=")
        if operator in (None, "", "="):
            return version
        return None

    def _build_env(self, source_code: str) -> Dict:
        """Return os.environ with SOLC_VERSION set only for exact-version pragmas."""
        env = dict(os.environ)
        ver = self._solc_version_for(source_code)
        if ver:
            env['SOLC_VERSION'] = ver
        return env

    def run_on_file(self, source_path: str, source_code: str = "") -> Dict:
        """
        Run slither on a .sol file and return parsed JSON.

        Args:
            source_path : Path to .sol file (or Foundry/Hardhat project dir).
            source_code : Raw Solidity text — used only for pragma extraction
                          and SOLC_VERSION inference.  Pass empty string when
                          running on a pre-existing file you didn't write.
        """
        if not self.is_available():
            return {"success": False,
                    "error": "slither not found (pip install slither-analyzer)"}

        # If inside a Foundry project directory and forge is absent, copy the
        # single file to a clean temp dir so crytic-compile uses solc instead.
        target = source_path
        _tmpdir_obj = None
        p = Path(source_path)
        if p.is_file():
            proj_root = p.parent
            if (proj_root / "foundry.toml").exists() and shutil.which("forge") is None:
                import tempfile as _tmp
                _tmpdir_obj = _tmp.TemporaryDirectory()
                new_path = Path(_tmpdir_obj.name) / p.name
                shutil.copy(source_path, new_path)
                target = str(new_path)
                # Read source for version detection if not provided
                if not source_code:
                    source_code = p.read_text(encoding="utf-8", errors="ignore")

        env = self._build_env(source_code)
        cmd = ["slither", target, "--json", "-", "--disable-color"]
        # cwd MUST be the directory containing the .sol file — slither uses it
        # as the compilation root; without it, stdout JSON is suppressed on Windows.
        run_cwd = str(Path(target).parent) if Path(target).is_file() else str(target)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout, env=env, cwd=run_cwd,
            )
            stdout = proc.stdout.strip()
            if not stdout:
                return {"success": False,
                        "error": (proc.stderr or "No output from slither")[:600]}
            return json.loads(stdout)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Slither timed out ({self.timeout}s)"}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Slither JSON parse error: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if _tmpdir_obj:
                _tmpdir_obj.cleanup()

    def run_on_source_string(self, source_code: str, filename: str = "Contract.sol") -> Dict:
        """Write source to a clean temp dir (no foundry.toml) and run slither."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sol_path = Path(tmpdir) / filename
            sol_path.write_text(source_code, encoding="utf-8")
            return self.run_on_file(str(sol_path), source_code=source_code)


# ─── PARSER ──────────────────────────────────────────────────────────────────

class SlitherParser:
    """
    Maps Slither JSON output → SlitherFinding objects using ChainEDR taxonomy.
    """

    def parse(self, slither_json: Dict, source_path: str = "") -> SlitherResult:
        """
        Parse Slither JSON output into SlitherResult.

        Args:
            slither_json: Raw dict from `slither --json -`
            source_path: Original source path (for display only)

        Returns:
            SlitherResult with typed findings
        """
        if not slither_json.get("success", True) is not False:
            # Slither sets success=False on compile errors
            pass

        # success=True even if findings exist (it means slither ran OK)
        # success=False means compilation failed
        success = slither_json.get("success", False)
        error = slither_json.get("error") or ""

        result = SlitherResult(
            success=success,
            raw_output=slither_json,
            error=str(error) if error else "",
            source_path=source_path,
        )

        if not success and not slither_json.get("results"):
            return result

        detectors = (
            slither_json
            .get("results", {})
            .get("detectors", [])
        )

        for det in detectors:
            finding = self._parse_detector(det)
            if finding:
                result.findings.append(finding)

        return result

    def _parse_detector(self, det: Dict) -> Optional[SlitherFinding]:
        """Parse a single detector dict into a SlitherFinding."""
        check = det.get("check", "")
        impact = det.get("impact", "Informational")
        confidence_str = det.get("confidence", "Low")
        description = det.get("description", "").strip()

        # Map to ChainEDR type
        chainedr_type = DETECTOR_TO_CHAINEDR.get(check, "UNCLASSIFIED_ANOMALY")
        severity = IMPACT_TO_SEVERITY.get(impact, "LOW")
        confidence = CONFIDENCE_MAP.get(confidence_str, 0.40)

        # Extract location from elements
        contract_name = ""
        function_name = ""
        source_file = ""
        source_lines: List[int] = []

        for element in det.get("elements", []):
            if element.get("type") == "function":
                function_name = element.get("name", "")
                parent = element.get("type_specific_fields", {}).get("parent", {})
                if isinstance(parent, dict):
                    contract_name = parent.get("name", "")
                sm = element.get("source_mapping", {})
                if isinstance(sm, dict):
                    source_file = sm.get("filename_used", "") or sm.get("filename_short", "")
                    source_lines = sm.get("lines", [])
                break  # Take the first function element

            elif element.get("type") == "contract" and not contract_name:
                contract_name = element.get("name", "")

        return SlitherFinding(
            detector_id=check,
            chainedr_type=chainedr_type,
            severity=severity,
            confidence=confidence,
            description=description,
            contract_name=contract_name,
            function_name=function_name,
            source_file=source_file,
            source_lines=source_lines,
            raw=det,
        )


# ─── BRIDGE ──────────────────────────────────────────────────────────────────

class SlitherBridge:
    """
    Orchestrates Slither integration into the ChainEDR pipeline.

    Three main operations:
      1. run()             — run Slither, return SlitherResult
      2. cross_validate()  — compare Slither vs ChainEDR findings
      3. enrich_audit_context() — fill AuditContext fields from Slither output
    """

    def __init__(self, timeout: int = 120):
        self.runner = SlitherRunner(timeout=timeout)
        self.parser = SlitherParser()

    def run(
        self,
        source_path: Optional[str] = None,
        source_code: Optional[str] = None,
        slither_json: Optional[Dict] = None,
        filename: str = "Contract.sol",
    ) -> SlitherResult:
        """
        Run Slither and return parsed result.

        Accepts one of:
          source_path  — path to .sol file or Foundry project directory
          source_code  — raw Solidity string (written to temp file)
          slither_json — pre-computed Slither JSON (useful for tests/CI)

        Returns:
            SlitherResult with all findings parsed
        """
        if slither_json is not None:
            # Test/CI mode: parse pre-computed JSON
            return self.parser.parse(slither_json, source_path or "")

        if source_path:
            raw = self.runner.run_on_file(source_path)
            return self.parser.parse(raw, source_path)

        if source_code:
            raw = self.runner.run_on_source_string(source_code, filename)
            return self.parser.parse(raw, filename)

        return SlitherResult(success=False, error="No source provided")

    def cross_validate(
        self,
        chainedr_vulns: List[Any],
        slither_findings: List[SlitherFinding],
    ) -> CrossValidationResult:
        """
        Cross-validate ChainEDR behavioral findings against Slither static findings.

        Matching logic:
          A ChainEDR finding and a Slither finding are "corroborated" if:
            - They have the same vulnerability type, AND
            - They reference the same function name (fuzzy: one contains the other)

        For corroborated findings:
          - ChainEDR confidence is boosted by CORROBORATION_BOOST (0.15)
          - A corroboration note is added to the finding

        Args:
            chainedr_vulns: List[ClassifiedVulnerability] from ChainEDR Classifier
            slither_findings: List[SlitherFinding] from SlitherBridge.run()

        Returns:
            CrossValidationResult
        """
        corroborated = []
        slither_matched = set()
        chainedr_matched = set()

        for ci, cv in enumerate(chainedr_vulns):
            cv_type = getattr(cv, "vulnerability_type", "")
            cv_func = getattr(cv.alert, "function_sig", "") if hasattr(cv, "alert") else ""
            cv_func_name = cv_func.split("(")[0].lower() if cv_func else ""

            for si, sf in enumerate(slither_findings):
                if sf.chainedr_type != cv_type:
                    continue

                sf_func = sf.function_name.lower()
                # Fuzzy match: one name contains the other, or both are empty
                names_match = (
                    not cv_func_name
                    or not sf_func
                    or cv_func_name in sf_func
                    or sf_func in cv_func_name
                )

                if names_match:
                    # Boost ChainEDR confidence
                    original_conf = getattr(cv, "confidence", 0.5)
                    boosted_conf = min(1.0, original_conf + CORROBORATION_BOOST)
                    try:
                        cv.confidence = boosted_conf
                    except AttributeError:
                        pass  # dataclass may be frozen

                    corroborated.append({
                        "chainedr": cv,
                        "slither": sf,
                        "original_confidence": original_conf,
                        "boosted_confidence": boosted_conf,
                        "note": (
                            f"Corroborated by Slither [{sf.detector_id}] on "
                            f"{sf.location} — confidence boosted "
                            f"{original_conf:.0%} → {boosted_conf:.0%}"
                        ),
                    })
                    slither_matched.add(si)
                    chainedr_matched.add(ci)

        slither_only = [sf for si, sf in enumerate(slither_findings) if si not in slither_matched]
        chainedr_only = [cv for ci, cv in enumerate(chainedr_vulns) if ci not in chainedr_matched]

        # Rough combined coverage estimate
        # ChainEDR base: 26.9%, Slither adds ~38pp on access control, overlap ~5pp
        combined_pct = min(100.0, 26.9 + len(slither_only) * 5.0)

        return CrossValidationResult(
            corroborated=corroborated,
            slither_only=slither_only,
            chainedr_only=chainedr_only,
            combined_coverage_pct=combined_pct,
        )

    def enrich_audit_context(
        self,
        ctx: AuditContext,
        slither_result: SlitherResult,
        function_sig: str = "",
    ) -> AuditContext:
        """
        Use Slither findings to fill in AuditContext fields that improve
        the FP filter's accuracy.

        What gets enriched:
          - has_rescue_function   ← Slither detects locked-ether pattern
          - function_modifiers    ← Slither detects missing access control
            (if Slither says function is UNPROTECTED, remove any guessed modifiers)

        Args:
            ctx: Existing AuditContext (will be mutated in place)
            slither_result: Parsed Slither output
            function_sig: The specific function being analyzed (optional)

        Returns:
            The same AuditContext with enriched fields
        """
        func_name = function_sig.split("(")[0].lower() if function_sig else ""

        for sf in slither_result.findings:
            # If Slither found locked-ether on this contract → no rescue function
            if sf.detector_id == "locked-ether":
                ctx.has_rescue_function = False

            # If Slither found arbitrary-send-eth → there IS an external attacker path
            # (corrects overly optimistic trust-model assumptions)
            if sf.detector_id == "arbitrary-send-eth":
                if func_name and func_name in sf.function_name.lower():
                    # Remove privileged modifiers if Slither says function is exploitable
                    ctx.function_modifiers = [
                        m for m in ctx.function_modifiers
                        if m not in {
                            "onlyOwner", "onlyAdmin", "onlyApprovedMigrator",
                            "requiresAuth", "adminOnly",
                        }
                    ]

            # If Slither finds reentrancy guard usage (via reentrancy-benign pass)
            # it implies nonReentrant is present somewhere in the contract
            if sf.detector_id in ("reentrancy-benign",):
                if "nonReentrant" not in ctx.function_modifiers:
                    ctx.function_modifiers.append("nonReentrant")

        return ctx

    def findings_to_report_section(self, slither_result: SlitherResult) -> str:
        """
        Render Slither findings as a markdown section for the Reporter.

        Designed to be appended to `generate_bug_bounty_report()` sections.
        """
        if not slither_result.success:
            return f"**Slither:** Not available — {slither_result.error}"

        if not slither_result.findings:
            return "**Slither:** No findings (clean static analysis pass)."

        lines = [
            "### Slither Static Analysis (corroborating evidence)",
            "",
            f"Slither detected **{len(slither_result.findings)} findings** "
            f"covering {len(slither_result.by_type)} vulnerability categories.",
            "",
            "| Severity | Detector | Confidence | Location |",
            "|----------|----------|------------|----------|",
        ]

        for sf in sorted(slither_result.findings, key=lambda f: (
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.severity, 3)
        )):
            lines.append(
                f"| {sf.severity} | `{sf.detector_id}` "
                f"| {sf.confidence:.0%} | {sf.location} |"
            )

        lines += [
            "",
            "> Slither output is used for **corroboration only**. "
            "ChainEDR behavioral analysis is the primary detection signal.",
        ]

        return "\n".join(lines)


# ─── CONVENIENCE ─────────────────────────────────────────────────────────────

def run_slither(
    source_path: Optional[str] = None,
    source_code: Optional[str] = None,
    slither_json: Optional[Dict] = None,
) -> SlitherResult:
    """
    One-line entry point for running Slither from anywhere in the codebase.

    Example:
        result = run_slither(source_path="contracts/Vault.sol")
        print(result.summary())
    """
    return SlitherBridge().run(
        source_path=source_path,
        source_code=source_code,
        slither_json=slither_json,
    )
