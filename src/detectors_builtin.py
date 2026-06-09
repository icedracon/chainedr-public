"""
ChainEDR Built-in Detector Wrappers

Architecture: ChainEDR does NOT duplicate Slither's Solidity checks.
Instead it orchestrates Slither as the primary Solidity analyzer and
adds its own NOVEL detectors that no other tool covers:
  - EIP-7702 (21 checks) — only tool in existence
  - EIP-7702 validation sandbox (9 ERC-7562 rules) — pre-execution AA analysis
  - Noir (7 checks) — only ZK circuit analyzer
  - Aztec (7 checks) — only Aztec.nr analyzer
  - Bridge/ZK verifier (5 checks) — cross-chain + proof verification
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import List

try:
    from .detector_plugin import (
        Detector, DetectorCategory, Finding, ScanOptions, ScanResult, Severity,
        register_detector,
    )
except ImportError:
    from detector_plugin import (
        Detector, DetectorCategory, Finding, ScanOptions, ScanResult, Severity,
        register_detector,
    )


def _import(name):
    """Import module from package or standalone."""
    try:
        return importlib.import_module(f".{name}", package=__package__)
    except (ImportError, TypeError):
        return importlib.import_module(name)


# ─────────────────────────────────────────────────────────────────────────────
# Solidity Static Analyzer
# ─────────────────────────────────────────────────────────────────────────────

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


@register_detector
class SlitherDetector(Detector):
    """Orchestrate Slither as the primary Solidity analyzer.

    ChainEDR does NOT reimplement Slither's 90+ detectors.
    Instead it runs Slither, normalizes output, applies FP filter,
    and merges with ChainEDR's novel checks.
    """
    name = "solidity"
    capabilities = [DetectorCategory.SOLIDITY.value]

    def discover(self, ctx) -> bool:
        return ctx.has_solidity

    def scan(self, ctx, opts: ScanOptions) -> ScanResult:
        import shutil
        import subprocess
        import json as _json

        result = ScanResult(detector_name=self.name)

        if not opts.use_slither or not shutil.which("slither"):
            result.error = "Slither not available (install: pip install slither-analyzer)"
            return result

        scan_dir = str(ctx.root)
        result.files_scanned = len(ctx.solidity_files)
        result.lines_scanned = sum(
            len(ctx.read_file(f).splitlines()) for f in ctx.solidity_files
        )

        try:
            proc = subprocess.run(
                ["slither", scan_dir, "--json", "-"],
                capture_output=True, text=True,
                timeout=opts.external_timeout,
            )
            data = _json.loads(proc.stdout) if proc.stdout.strip() else {}
        except (subprocess.TimeoutExpired, _json.JSONDecodeError, FileNotFoundError):
            result.error = "Slither execution failed"
            return result

        findings: List[Finding] = []
        for det_result in data.get("results", {}).get("detectors", []):
            sev = det_result.get("impact", "Low").upper()
            check = det_result.get("check", "unknown")
            desc = det_result.get("description", "")
            first_elem = (det_result.get("elements") or [{}])[0] if det_result.get("elements") else {}
            src_map = first_elem.get("source_mapping", {})
            filename = src_map.get("filename_relative", "")
            line = src_map.get("lines", [0])[0] if src_map.get("lines") else 0

            findings.append(Finding(
                detector=self.name,
                rule_id=f"SL-{check}",
                severity=_SEV_MAP.get(sev, Severity.LOW),
                title=f"[Slither] {check}: {desc[:80]}",
                description=desc,
                file_path=filename,
                line=line,
                category=DetectorCategory.SOLIDITY.value,
                confidence={"HIGH": 0.90, "MEDIUM": 0.70, "LOW": 0.50}.get(
                    det_result.get("confidence", "Medium").upper(), 0.60
                ),
            ))

        result.findings = findings
        return result


# ─────────────────────────────────────────────────────────────────────────────
# EIP-7702 Detector
# ─────────────────────────────────────────────────────────────────────────────

@register_detector
class EIP7702PluginDetector(Detector):
    name = "eip7702"
    capabilities = [DetectorCategory.EIP7702.value]

    def discover(self, ctx) -> bool:
        return ctx.has_solidity

    def scan(self, ctx, opts: ScanOptions) -> ScanResult:
        mod = _import("eip7702_detector")
        EIP7702Detector = mod.EIP7702Detector

        result = ScanResult(detector_name=self.name)
        findings: List[Finding] = []
        det = EIP7702Detector()
        sources = {}

        for sol_file in ctx.solidity_files:
            source = ctx.read_file(sol_file)
            rel_path = str(sol_file.relative_to(ctx.root)) if sol_file.is_relative_to(ctx.root) else sol_file.name
            sources[rel_path] = source
            result.files_scanned += 1
            result.lines_scanned += len(source.splitlines())

        deep = bool(getattr(opts, "deep", False) and getattr(opts, "use_ast", True))
        eip_results, _project_context = det.scan_files(sources, deep=deep)
        for rel_path, f7702 in eip_results:
            findings.append(Finding(
                detector=self.name,
                rule_id=f7702.check_id,
                severity=_SEV_MAP.get(f7702.severity, Severity.MEDIUM),
                title=f7702.title,
                description=f7702.description,
                location=f7702.location,
                file_path=rel_path,
                category=DetectorCategory.EIP7702.value,
                cwe=f7702.cwe,
                confidence=f7702.confidence,
                fix_suggestion=f7702.recommendation,
                metadata={
                    **f7702.sandbox_metadata(),
                    "semantic_context": f7702.semantic_context,
                    "proof_recipe": f7702.proof_metadata(),
                },
            ))

        try:
            proof_mod = _import("proof_adapters")
            proof_mod.attach_proof_adapters(findings)
        except Exception:
            pass

        result.findings = findings
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Extended Pectra Detector
# ─────────────────────────────────────────────────────────────────────────────

@register_detector
class ExtendedPectraDetector(Detector):
    """Opt-in experimental Pectra-era checks kept out of default scans."""

    name = "extended_pectra"
    capabilities = [DetectorCategory.EIP7702.value, DetectorCategory.SOLIDITY.value]

    def discover(self, ctx) -> bool:
        return ctx.has_solidity

    def scan(self, ctx, opts: ScanOptions) -> ScanResult:
        result = ScanResult(detector_name=self.name)
        if not getattr(opts, "extended", False):
            return result

        findings: List[Finding] = []
        runners = [
            ("eip7702_ext", "eip7702_extensions", "run_extended_checks"),
            ("erc7821", "erc7821_checker", "check_erc7821"),
            ("mev", "mev_and_erc6900_checker", "check_mev_protection"),
            ("erc6900", "mev_and_erc6900_checker", "check_erc6900"),
        ]

        for sol_file in ctx.solidity_files:
            source = ctx.read_file(sol_file)
            rel_path = str(sol_file.relative_to(ctx.root)) if sol_file.is_relative_to(ctx.root) else sol_file.name
            result.files_scanned += 1
            result.lines_scanned += len(source.splitlines())

            for category, module_name, function_name in runners:
                try:
                    check_fn = getattr(_import(module_name), function_name)
                    raw_findings = check_fn(source)
                except Exception:
                    continue

                for raw in raw_findings:
                    loc = getattr(raw, "location", "") or ""
                    line = 0
                    m = re.search(r"[Ll](\d+)", loc)
                    if m:
                        line = int(m.group(1))

                    findings.append(Finding(
                        detector=self.name,
                        rule_id=getattr(raw, "check_id", category),
                        severity=_SEV_MAP.get(
                            str(getattr(raw, "severity", "MEDIUM")).upper(),
                            Severity.MEDIUM,
                        ),
                        title=getattr(raw, "title", "Extended Pectra finding"),
                        description=getattr(raw, "description", ""),
                        location=loc,
                        file_path=rel_path,
                        line=line,
                        category=category,
                        cwe=getattr(raw, "cwe", ""),
                        confidence=getattr(raw, "confidence", 0.5),
                        fix_suggestion=getattr(raw, "recommendation", ""),
                        metadata={
                            "experimental": True,
                            "extended": True,
                            "source_module": module_name,
                        },
                    ))

        result.findings = findings
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Bridge + ZK Verifier Detector
# ─────────────────────────────────────────────────────────────────────────────

@register_detector
class BridgeZKDetector(Detector):
    name = "bridge_zk"
    capabilities = [DetectorCategory.BRIDGE.value, DetectorCategory.ZK_VERIFIER.value]

    def discover(self, ctx) -> bool:
        return ctx.has_solidity

    def scan(self, ctx, opts: ScanOptions) -> ScanResult:
        mod = _import("bridge_detectors")
        check_bridge_validation = mod.check_bridge_validation
        check_bridge_signature_gaps = mod.check_bridge_signature_gaps
        check_zk_misconfig = mod.check_zk_misconfig

        result = ScanResult(detector_name=self.name)
        findings: List[Finding] = []

        # Build filename->content map (bridge_detectors API)
        source_map = {}
        for sol_file in ctx.solidity_files:
            source = ctx.read_file(sol_file)
            rel_path = str(sol_file.relative_to(ctx.root)) if sol_file.is_relative_to(ctx.root) else sol_file.name
            source_map[rel_path] = source
            result.files_scanned += 1
            result.lines_scanned += len(source.splitlines())

        for bf in check_bridge_validation(source_map):
            findings.append(Finding(
                detector=self.name,
                rule_id=bf.get("check", "BRIDGE"),
                severity=_SEV_MAP.get(bf.get("severity", "HIGH"), Severity.HIGH),
                title=bf.get("title", "Bridge validation gap"),
                description=bf.get("description", ""),
                file_path=bf.get("file", ""),
                category=DetectorCategory.BRIDGE.value,
                cwe=bf.get("cwe", ""),
                confidence=bf.get("confidence", 0.75),
            ))

        for sf in check_bridge_signature_gaps(source_map):
            findings.append(Finding(
                detector=self.name,
                rule_id=sf.get("check", "BRIDGE_SIG"),
                severity=_SEV_MAP.get(sf.get("severity", "HIGH"), Severity.HIGH),
                title=sf.get("title", "Bridge signature gap"),
                description=sf.get("description", ""),
                file_path=sf.get("file", ""),
                category=DetectorCategory.BRIDGE.value,
                cwe=sf.get("cwe", ""),
                confidence=sf.get("confidence", 0.75),
            ))

        for zf in check_zk_misconfig(source_map):
            findings.append(Finding(
                detector=self.name,
                rule_id=zf.get("check", "ZK"),
                severity=_SEV_MAP.get(zf.get("severity", "MEDIUM"), Severity.MEDIUM),
                title=zf.get("title", "ZK verifier misconfiguration"),
                description=zf.get("description", ""),
                file_path=zf.get("file", ""),
                category=DetectorCategory.ZK_VERIFIER.value,
                cwe=zf.get("cwe", ""),
                confidence=zf.get("confidence", 0.70),
            ))

        result.findings = findings
        return result
