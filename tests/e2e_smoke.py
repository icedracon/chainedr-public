"""
ChainEDR E2E Smoke Test

Runs `Hunter.scan_source_directory()` on real audit targets.
Each target reports: pass/fail, runtime, finding count by severity, errors.

Usage:
    python tests/e2e_smoke.py                      # all targets
    python tests/e2e_smoke.py infinifi             # one target by name
    python tests/e2e_smoke.py --timeout 120        # custom timeout
    python tests/e2e_smoke.py --json out.json      # JSON output

Exit code: 0 if all pass, non-zero = # failed targets.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

# Allow standalone run from repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

AUDIT_TARGETS_ROOT = Path("C:/Users/zevs/Documents/audit_targets")


# ── Target definitions ───────────────────────────────────────────────────────
# Each entry: (name, relative path, source subdirectory, expected_min_findings)
TARGETS: List[Dict] = [
    {
        "name": "infinifi-protocol",
        "path": "infinifi-protocol",
        "src_subdir": "src",
        "min_findings": 10,
        "must_contain": ["safety_buffer_waterfall", "cross_contract_oracle_taint"],
        "description": "Confirmed waterfall cliff + oracle taint bugs",
    },
    {
        "name": "hyperbridge",
        "path": "hyperbridge",
        "src_subdir": "evm/src",  # adjust if needed
        "min_findings": 5,
        "must_contain": [],
        "description": "Cross-chain bridge — complex inheritance",
    },
    {
        "name": "paxos-gold",
        "path": "paxos-gold-contract",
        "src_subdir": "contracts",
        "min_findings": 1,
        "must_contain": [],
        "description": "Token contract — should be clean",
    },
    {
        "name": "pyusd",
        "path": "pyusd-contract",
        "src_subdir": "contracts",
        "min_findings": 1,
        "must_contain": [],
        "description": "PayPal USD stablecoin",
    },
    {
        "name": "solidity-merkle-trees",
        "path": "solidity-merkle-trees",
        "src_subdir": "src",
        "min_findings": 0,
        "min_fp_labeled_ratio": 0.7,   # >=70% of findings should be labeled FALSE_POSITIVE
        "must_contain": [],
        "description": "Merkle tree library — FP labeling regression (no findings hidden)",
    },
    {
        "name": "dex-router",
        "path": "DEX-Router-EVM-V1",
        "src_subdir": "contracts",
        "min_findings": 3,
        "must_contain": [],
        "description": "DEX router — slippage / sandwich surface",
    },
    {
        "name": "usdg",
        "path": "usdg-contract",
        "src_subdir": "contracts",
        "min_findings": 0,
        "must_contain": [],
        "description": "USDG stablecoin",
    },
]


# ── Result model ─────────────────────────────────────────────────────────────

@dataclass
class TargetResult:
    name: str
    description: str
    status: str               # PASS | FAIL | SKIP
    runtime_sec: float
    finding_count: int
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_check: Dict[str, int] = field(default_factory=dict)
    by_fp_verdict: Dict[str, int] = field(default_factory=dict)
    found_required: List[str] = field(default_factory=list)
    missing_required: List[str] = field(default_factory=list)
    error: Optional[str] = None
    error_trace: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Runner ───────────────────────────────────────────────────────────────────

def run_target(target: Dict, timeout: int = 180) -> TargetResult:
    """Run scan on one target. Catches exceptions, measures runtime."""
    name = target["name"]
    target_path = AUDIT_TARGETS_ROOT / target["path"]
    src_dir = target_path / target["src_subdir"]

    result = TargetResult(
        name=name,
        description=target.get("description", ""),
        status="FAIL",
        runtime_sec=0.0,
        finding_count=0,
    )

    if not src_dir.exists():
        result.status = "SKIP"
        result.error = f"path missing: {src_dir}"
        return result

    # Find Solidity files
    sol_files = list(src_dir.rglob("*.sol"))
    sol_files = [
        f for f in sol_files
        if not any(skip in str(f).lower()
                   for skip in ["/test", "\\test", "/mock", "\\mock", ".t.sol"])
    ]
    if not sol_files:
        result.status = "SKIP"
        result.error = f"no .sol files in {src_dir}"
        return result

    # Import inside try so missing modules don't crash all targets
    try:
        from chainedr.hunter import Hunter
    except ImportError as e:
        result.error = f"import Hunter failed: {e}"
        return result

    t0 = time.monotonic()
    try:
        # Suppress detector noise
        logging.disable(logging.WARNING)
        # Smoke is regression-only — skip external tools for speed
        findings = Hunter.scan_source_directory(
            str(src_dir), external_tools=False
        )
    except Exception as e:
        result.runtime_sec = round(time.monotonic() - t0, 2)
        result.error = f"{type(e).__name__}: {e}"
        result.error_trace = traceback.format_exc()
        return result
    finally:
        logging.disable(logging.NOTSET)

    result.runtime_sec = round(time.monotonic() - t0, 2)
    result.finding_count = len(findings)

    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        result.by_severity[sev] = result.by_severity.get(sev, 0) + 1
        chk = f.get("check", "unknown")
        result.by_check[chk] = result.by_check.get(chk, 0) + 1
        # Track FP analyzer verdict distribution
        fp = f.get("fp_analysis", {})
        verdict = fp.get("verdict", "MISSING")
        result.by_fp_verdict[verdict] = result.by_fp_verdict.get(verdict, 0) + 1

    # Check required findings
    found_checks = set(result.by_check.keys())
    required = target.get("must_contain", [])
    result.found_required = [c for c in required if c in found_checks]
    result.missing_required = [c for c in required if c not in found_checks]

    # Pass criteria: ran without exception AND meets min/max and ratio constraints
    min_findings = target.get("min_findings", 0)
    max_findings = target.get("max_findings")
    min_fp_labeled_ratio = target.get("min_fp_labeled_ratio")

    passes_count = (
        result.finding_count >= min_findings
        and (max_findings is None or result.finding_count <= max_findings)
    )

    passes_fp_ratio = True
    if min_fp_labeled_ratio is not None and result.finding_count > 0:
        fp_count = result.by_fp_verdict.get("FALSE_POSITIVE", 0)
        ratio = fp_count / result.finding_count
        passes_fp_ratio = ratio >= min_fp_labeled_ratio

    if passes_count and passes_fp_ratio and not result.missing_required:
        result.status = "PASS"
    else:
        details = []
        if result.finding_count < min_findings:
            details.append(f"only {result.finding_count}/{min_findings} findings")
        if max_findings is not None and result.finding_count > max_findings:
            details.append(f"too many: {result.finding_count} > max {max_findings}")
        if min_fp_labeled_ratio is not None and not passes_fp_ratio:
            fp_count = result.by_fp_verdict.get("FALSE_POSITIVE", 0)
            details.append(
                f"FP labeled ratio {fp_count}/{result.finding_count}="
                f"{fp_count/max(1,result.finding_count):.0%} < required "
                f"{min_fp_labeled_ratio:.0%}"
            )
        if result.missing_required:
            details.append(f"missing: {','.join(result.missing_required)}")
        result.error = "; ".join(details)

    return result


# ── CLI / output ─────────────────────────────────────────────────────────────

def print_target(r: TargetResult) -> None:
    icon = {"PASS": "[OK]  ", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}.get(r.status, "[?]")
    print(f"\n{icon} {r.name:25s} {r.runtime_sec:>6.1f}s  "
          f"findings={r.finding_count:3d}")
    if r.description:
        print(f"       {r.description}")
    if r.by_severity:
        sev_str = " ".join(f"{k}={v}" for k, v in sorted(
            r.by_severity.items(),
            key=lambda kv: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(kv[0], 9)
        ))
        print(f"       severity: {sev_str}")
    if r.found_required:
        print(f"       required hits: {', '.join(r.found_required)}")
    if r.missing_required:
        print(f"       MISSING required: {', '.join(r.missing_required)}")
    if r.error:
        print(f"       error: {r.error}")
    if r.error_trace:
        print(f"       trace:")
        for line in r.error_trace.strip().splitlines()[-5:]:
            print(f"         {line}")


def print_summary(results: List[TargetResult]) -> None:
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    skipped = sum(1 for r in results if r.status == "SKIP")
    total_runtime = sum(r.runtime_sec for r in results)
    total_findings = sum(r.finding_count for r in results)

    print(f"\n{'='*64}")
    print(f"  Summary: {passed} PASS, {failed} FAIL, {skipped} SKIP")
    print(f"  Total runtime: {total_runtime:.1f}s  "
          f"Total findings: {total_findings}")
    print(f"{'='*64}")


def main():
    parser = argparse.ArgumentParser(description="ChainEDR E2E smoke test")
    parser.add_argument("targets", nargs="*", help="Target names to run (default: all)")
    parser.add_argument("--timeout", type=int, default=180,
                        help="Per-target timeout in seconds (default 180)")
    parser.add_argument("--json", metavar="PATH",
                        help="Write JSON results to file")
    parser.add_argument("--list", action="store_true",
                        help="List available targets and exit")
    args = parser.parse_args()

    if args.list:
        for t in TARGETS:
            print(f"  {t['name']:25s}  {t.get('description', '')}")
        return 0

    selected = TARGETS
    if args.targets:
        selected = [t for t in TARGETS if t["name"] in args.targets]
        if not selected:
            print(f"No matching targets. Available: {[t['name'] for t in TARGETS]}")
            return 2

    print(f"ChainEDR E2E Smoke — {len(selected)} target(s)")
    print(f"{'='*64}")

    results: List[TargetResult] = []
    for target in selected:
        print(f"\n>>> {target['name']} ({target['path']}/{target['src_subdir']})")
        r = run_target(target, timeout=args.timeout)
        results.append(r)
        print_target(r)

    print_summary(results)

    if args.json:
        Path(args.json).write_text(
            json.dumps([r.to_dict() for r in results], indent=2)
        )
        print(f"\nJSON results: {args.json}")

    failed = sum(1 for r in results if r.status == "FAIL")
    return failed


if __name__ == "__main__":
    # Force UTF-8 output on Windows — only in standalone mode. Doing this at
    # import time replaces the stdout/stderr buffers pytest captures, which
    # breaks collection (I/O operation on closed file).
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    sys.exit(main())
