"""
Scan real-world EIP-7702 / AA targets and produce structured results.

Targets:
  1. eth-infinitism/account-abstraction  — ERC-4337 reference implementation
  2. MetaMask/delegation-framework       — production EIP-7702 delegation contracts
  3. OpenZeppelin/contracts v5            — clean baseline (expect 0 FP on core)
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eip7702_detector import EIP7702Detector
from eip7702_validation import EIP7702ValidationDetector
from detector_plugin import ScanOptions
from project_context import discover_project


def scan_eip7702_static(target_dir: Path) -> dict:
    det = EIP7702Detector()
    sol_files = sorted(target_dir.rglob("*.sol"))
    findings = []
    affected = 0
    total_lines = 0

    start = time.perf_counter()
    for p in sol_files:
        src = p.read_text(encoding="utf-8", errors="ignore")
        total_lines += len(src.splitlines())
        if not det.is_affected(src):
            continue
        affected += 1
        for f in det.check(src):
            rel = str(p.relative_to(target_dir))
            findings.append({
                "check_id": f.check_id,
                "severity": f.severity,
                "title": f.title,
                "file": rel,
                "location": f.location,
                "confidence": round(f.confidence, 2),
                "cwe": f.cwe,
                "sandbox_boundary": f.sandbox_metadata().get("sandbox_boundary", ""),
                "bypass_class": f.sandbox_metadata().get("sandbox_bypass_class", ""),
            })
    elapsed = time.perf_counter() - start

    return {
        "detector": "eip7702_static",
        "target": str(target_dir),
        "total_files": len(sol_files),
        "affected_files": affected,
        "total_lines": total_lines,
        "findings_count": len(findings),
        "elapsed_s": round(elapsed, 3),
        "findings": findings,
    }


def scan_eip7702_validation(target_dir: Path) -> dict:
    det = EIP7702ValidationDetector()
    ctx = discover_project(target_dir)
    opts = ScanOptions(use_slither=False, use_ast=False)

    start = time.perf_counter()
    result = det._timed_scan(ctx, opts)
    elapsed = time.perf_counter() - start

    findings = []
    for f in result.findings:
        findings.append({
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "title": f.title,
            "file": f.file_path,
            "confidence": round(f.confidence, 2),
            "cwe": f.cwe,
        })

    return {
        "detector": "eip7702_validation",
        "target": str(target_dir),
        "files_scanned": result.files_scanned,
        "lines_scanned": result.lines_scanned,
        "findings_count": len(findings),
        "elapsed_s": round(elapsed, 3),
        "findings": findings,
    }


def summarize(results: list[dict]) -> dict:
    total_findings = sum(r["findings_count"] for r in results)
    total_files = sum(r.get("total_files", r.get("files_scanned", 0)) for r in results)

    checks_triggered = set()
    by_severity = defaultdict(int)
    by_check = defaultdict(int)

    for r in results:
        for f in r["findings"]:
            cid = f.get("check_id") or f.get("rule_id")
            sev = f.get("severity", "UNKNOWN")
            checks_triggered.add(cid)
            by_severity[sev] += 1
            by_check[cid] += 1

    return {
        "total_findings": total_findings,
        "total_files": total_files,
        "unique_checks_triggered": sorted(checks_triggered),
        "checks_triggered_count": len(checks_triggered),
        "by_severity": dict(sorted(by_severity.items())),
        "by_check": dict(sorted(by_check.items())),
    }


def main():
    targets = {
        "eth-infinitism": ROOT / "test_targets" / "account-abstraction" / "contracts",
        "metamask": ROOT / "test_targets" / "delegation-framework" / "src",
    }

    all_results = []
    for name, target_dir in targets.items():
        if not target_dir.exists():
            print(f"SKIP {name}: {target_dir} not found")
            continue

        print(f"\n{'='*60}")
        print(f"Scanning: {name} ({target_dir})")
        print(f"{'='*60}")

        static = scan_eip7702_static(target_dir)
        print(f"  Static: {static['findings_count']} findings in {static['affected_files']}/{static['total_files']} files ({static['elapsed_s']}s)")
        all_results.append(static)

        validation = scan_eip7702_validation(target_dir)
        print(f"  Validation: {validation['findings_count']} findings in {validation['files_scanned']} files ({validation['elapsed_s']}s)")
        all_results.append(validation)

    summary = summarize(all_results)
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Total findings: {summary['total_findings']}")
    print(f"Unique checks: {summary['checks_triggered_count']}/30")
    print(f"Checks: {', '.join(summary['unique_checks_triggered'])}")
    print(f"By severity: {summary['by_severity']}")

    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "results": all_results,
        "summary": summary,
    }

    out_path = ROOT / "paper" / "results" / "real_target_scan.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
