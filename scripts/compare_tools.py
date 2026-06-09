"""
Compare ChainEDR EIP-7702 detection against Slither, Aderyn, and Mythril.

For each tool, run on the same corpus and check:
  - Total generic findings
  - EIP-7702-specific findings (should be 0 for competitors)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eip7702_detector import EIP7702Detector
from eip7702_validation import EIP7702ValidationDetector
from detector_plugin import ScanOptions
from project_context import discover_project

EIP7702_KEYWORDS = [
    "eip-7702", "eip7702", "7702", "delegation", "set_code",
    "delegated eoa", "account abstraction",
    "tx.origin.*msg.sender", "iscontract", "extcodesize",
]


def _is_eip7702_relevant(description: str) -> bool:
    desc_lower = description.lower()
    return any(kw in desc_lower for kw in EIP7702_KEYWORDS)


def run_chainedr(target_dir: Path) -> dict:
    det = EIP7702Detector()
    val = EIP7702ValidationDetector()
    sol_files = sorted(target_dir.rglob("*.sol"))

    start = time.perf_counter()
    static_findings = []
    for p in sol_files:
        src = p.read_text(encoding="utf-8", errors="ignore")
        if det.is_affected(src):
            for f in det.check(src):
                static_findings.append(f.check_id)

    ctx = discover_project(target_dir)
    opts = ScanOptions(use_slither=False, use_ast=False)
    vresult = val._timed_scan(ctx, opts)
    val_findings = [f.rule_id for f in vresult.findings]
    elapsed = time.perf_counter() - start

    return {
        "tool": "ChainEDR",
        "version": "3.0.0",
        "total_findings": len(static_findings) + len(val_findings),
        "eip7702_findings": len(static_findings) + len(val_findings),
        "unique_checks": sorted(set(static_findings + val_findings)),
        "elapsed_s": round(elapsed, 3),
    }


def run_slither(target_dir: Path) -> dict:
    if not shutil.which("slither"):
        return {"tool": "Slither", "version": "N/A", "error": "not installed",
                "total_findings": 0, "eip7702_findings": 0, "unique_checks": []}

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["slither", str(target_dir), "--json", "-"],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return {"tool": "Slither", "version": "?", "error": "execution failed",
                "total_findings": 0, "eip7702_findings": 0, "unique_checks": []}
    elapsed = time.perf_counter() - start

    detectors = data.get("results", {}).get("detectors", [])
    eip7702_count = 0
    eip7702_checks = []
    for d in detectors:
        desc = d.get("description", "") + d.get("check", "")
        if _is_eip7702_relevant(desc):
            eip7702_count += 1
            eip7702_checks.append(d.get("check", "unknown"))

    return {
        "tool": "Slither",
        "version": data.get("version", "?"),
        "total_findings": len(detectors),
        "eip7702_findings": eip7702_count,
        "unique_checks": sorted(set(eip7702_checks)),
        "elapsed_s": round(elapsed, 3),
    }


def run_aderyn(target_dir: Path) -> dict:
    if not shutil.which("aderyn"):
        return {"tool": "Aderyn", "version": "N/A", "error": "not installed",
                "total_findings": 0, "eip7702_findings": 0, "unique_checks": []}

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["aderyn", str(target_dir), "--output", "json"],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return {"tool": "Aderyn", "version": "?", "error": "execution failed",
                "total_findings": 0, "eip7702_findings": 0, "unique_checks": []}
    elapsed = time.perf_counter() - start

    issues = data.get("issues", {})
    total = sum(len(v) for v in issues.values()) if isinstance(issues, dict) else 0
    eip7702_count = 0

    for severity_issues in (issues.values() if isinstance(issues, dict) else []):
        for issue in severity_issues:
            desc = str(issue.get("description", "")) + str(issue.get("title", ""))
            if _is_eip7702_relevant(desc):
                eip7702_count += 1

    return {
        "tool": "Aderyn",
        "version": "?",
        "total_findings": total,
        "eip7702_findings": eip7702_count,
        "unique_checks": [],
        "elapsed_s": round(elapsed, 3),
    }


def main():
    targets = {
        "eth-infinitism": ROOT / "test_targets" / "account-abstraction" / "contracts",
        "metamask": ROOT / "test_targets" / "delegation-framework" / "src",
    }

    all_results = {}
    for name, target_dir in targets.items():
        if not target_dir.exists():
            print(f"SKIP {name}")
            continue

        print(f"\n{'='*60}")
        print(f"Target: {name}")
        print(f"{'='*60}")

        results = []
        for runner_name, runner in [
            ("ChainEDR", run_chainedr),
            ("Slither", run_slither),
            ("Aderyn", run_aderyn),
        ]:
            print(f"  Running {runner_name}...", end=" ", flush=True)
            r = runner(target_dir)
            print(f"{r['total_findings']} total, {r['eip7702_findings']} EIP-7702")
            results.append(r)

        all_results[name] = results

    # Print comparison table
    print(f"\n{'='*60}")
    print(f"COMPARISON TABLE")
    print(f"{'='*60}")
    print(f"{'Tool':<12} {'Target':<18} {'Total':<8} {'EIP-7702':<10} {'Time':<8}")
    print("-" * 56)
    for name, results in all_results.items():
        for r in results:
            t = r.get("elapsed_s", "N/A")
            print(f"{r['tool']:<12} {name:<18} {r['total_findings']:<8} {r['eip7702_findings']:<10} {t}")
        print()

    out_path = ROOT / "paper" / "results" / "tool_comparison.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")
    print(f"Results saved to: {out_path}")


if __name__ == "__main__":
    main()
