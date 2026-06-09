"""
Performance benchmark for ChainEDR EIP-7702 detection.

Measures: per-file scan time, throughput (LOC/sec), memory peak.
"""
from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path
from statistics import mean, median

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eip7702_detector import EIP7702Detector


def benchmark_files(sol_files: list[Path]) -> dict:
    det = EIP7702Detector()
    per_file = []

    tracemalloc.start()
    total_start = time.perf_counter()

    for p in sol_files:
        src = p.read_text(encoding="utf-8", errors="ignore")
        lines = len(src.splitlines())
        chars = len(src)

        start = time.perf_counter()
        affected = det.is_affected(src)
        findings = det.check(src) if affected else []
        elapsed = time.perf_counter() - start

        per_file.append({
            "file": p.name,
            "lines": lines,
            "chars": chars,
            "affected": affected,
            "findings": len(findings),
            "time_ms": round(elapsed * 1000, 2),
            "loc_per_sec": round(lines / elapsed) if elapsed > 0 else 0,
        })

    total_elapsed = time.perf_counter() - total_start
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    times = [f["time_ms"] for f in per_file]
    total_lines = sum(f["lines"] for f in per_file)
    total_findings = sum(f["findings"] for f in per_file)

    return {
        "files": len(per_file),
        "total_lines": total_lines,
        "total_findings": total_findings,
        "total_time_ms": round(total_elapsed * 1000, 2),
        "peak_memory_mb": round(peak_memory / 1024 / 1024, 2),
        "throughput_loc_per_sec": round(total_lines / total_elapsed) if total_elapsed > 0 else 0,
        "throughput_files_per_sec": round(len(per_file) / total_elapsed, 1) if total_elapsed > 0 else 0,
        "per_file_ms": {
            "mean": round(mean(times), 2) if times else 0,
            "median": round(median(times), 2) if times else 0,
            "min": round(min(times), 2) if times else 0,
            "max": round(max(times), 2) if times else 0,
            "p95": round(sorted(times)[int(len(times) * 0.95)] if times else 0, 2),
        },
        "per_file": per_file,
    }


def main():
    targets = {
        "eth-infinitism": ROOT / "test_targets" / "account-abstraction" / "contracts",
        "metamask": ROOT / "test_targets" / "delegation-framework" / "src",
        "oz-v5": ROOT / "test_targets" / "oz-v5",
    }

    results = {}
    for name, target_dir in targets.items():
        if not target_dir.exists():
            print(f"SKIP {name}")
            continue

        sol_files = sorted(target_dir.rglob("*.sol"))
        if not sol_files:
            print(f"SKIP {name}: no .sol files")
            continue

        print(f"\nBenchmarking: {name} ({len(sol_files)} files)")
        r = benchmark_files(sol_files)
        results[name] = r
        print(f"  Time: {r['total_time_ms']}ms | "
              f"Lines: {r['total_lines']} | "
              f"Throughput: {r['throughput_loc_per_sec']} LOC/s | "
              f"Memory: {r['peak_memory_mb']}MB | "
              f"Findings: {r['total_findings']}")
        print(f"  Per-file: mean={r['per_file_ms']['mean']}ms "
              f"median={r['per_file_ms']['median']}ms "
              f"p95={r['per_file_ms']['p95']}ms")

    # Combined summary
    all_files = []
    for name, target_dir in targets.items():
        if target_dir.exists():
            all_files.extend(sorted(target_dir.rglob("*.sol")))

    if all_files:
        print(f"\nCombined benchmark: {len(all_files)} files")
        combined = benchmark_files(all_files)
        results["combined"] = combined
        print(f"  Time: {combined['total_time_ms']}ms | "
              f"Lines: {combined['total_lines']} | "
              f"Throughput: {combined['throughput_loc_per_sec']} LOC/s | "
              f"Memory: {combined['peak_memory_mb']}MB")

    out_path = ROOT / "paper" / "results" / "performance.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Strip per_file detail for output (too large)
    compact = {}
    for name, r in results.items():
        compact[name] = {k: v for k, v in r.items() if k != "per_file"}
    out_path.write_text(json.dumps(compact, indent=2), encoding="utf-8")
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
