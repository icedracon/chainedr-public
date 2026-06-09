"""ChainEDR Performance Benchmark — measures every layer."""
import sys, os, time, tracemalloc, json, statistics
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

results = {}

def bench(name, func, *args, runs=3, **kwargs):
    times = []
    peak_mems = []
    for _ in range(runs):
        tracemalloc.start()
        t0 = time.perf_counter()
        ret = func(*args, **kwargs)
        elapsed = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append(elapsed)
        peak_mems.append(peak / 1024 / 1024)
    r = {
        "mean_s": round(statistics.mean(times), 4),
        "min_s": round(min(times), 4),
        "max_s": round(max(times), 4),
        "peak_mb": round(max(peak_mems), 2),
    }
    results[name] = r
    print(f"  {name:45s} {r['mean_s']:8.3f}s  peak={r['peak_mb']:6.1f}MB")
    return ret

# ═══════════════════════════════════════════════════════════════
# 1. STATIC ANALYSIS — Hunter on single files
# ═══════════════════════════════════════════════════════════════
print("\n=== 1. STATIC ANALYSIS (Hunter) ===")

from src.static_analyzer import SolidityStaticAnalyzer as StaticAnalyzer

small_sol = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SimpleToken {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

medium_sol_lines = ["pragma solidity ^0.8.0;", "contract Medium {"]
for i in range(50):
    medium_sol_lines.append(f"    uint256 public var{i};")
    medium_sol_lines.append(f"    function fn{i}(uint256 x) external {{")
    medium_sol_lines.append(f"        var{i} = x;")
    medium_sol_lines.append(f"        (bool ok,) = msg.sender.call{{value: x}}(\"\");")
    medium_sol_lines.append(f"        require(ok);")
    medium_sol_lines.append(f"    }}")
medium_sol_lines.append("}")
medium_sol = "\n".join(medium_sol_lines)

large_sol_lines = ["pragma solidity ^0.8.0;", "contract Large {"]
for i in range(200):
    large_sol_lines.append(f"    mapping(address => uint256) public map{i};")
    large_sol_lines.append(f"    function action{i}(address to, uint256 amt) external {{")
    large_sol_lines.append(f"        require(map{i}[msg.sender] >= amt);")
    large_sol_lines.append(f"        map{i}[msg.sender] -= amt;")
    large_sol_lines.append(f"        (bool ok,) = to.call{{value: amt}}(\"\");")
    large_sol_lines.append(f"        require(ok);")
    large_sol_lines.append(f"        map{i}[to] += amt;")
    large_sol_lines.append(f"    }}")
large_sol_lines.append("}")
large_sol = "\n".join(large_sol_lines)

sa_fast = StaticAnalyzer()
bench("hunter: 12-line contract", sa_fast.analyze, small_sol, "small.sol", use_slither=False, use_ast=False)
bench("hunter: 300-line contract (50 fn)", sa_fast.analyze, medium_sol, "medium.sol", use_slither=False, use_ast=False)
bench("hunter: 1600-line contract (200 fn)", sa_fast.analyze, large_sol, "large.sol", use_slither=False, use_ast=False)

# ═══════════════════════════════════════════════════════════════
# 2. STATIC ANALYZER (full pipeline with all detectors)
# ═══════════════════════════════════════════════════════════════
print("\n=== 2. STATIC ANALYZER (all detectors) ===")

from src.static_analyzer import SolidityStaticAnalyzer as StaticAnalyzer

sa = StaticAnalyzer()
bench("analyzer: 12-line contract", sa.analyze, small_sol, "small.sol", use_slither=False, use_ast=False)
bench("analyzer: 300-line contract", sa.analyze, medium_sol, "medium.sol", use_slither=False, use_ast=False)
bench("analyzer: 1600-line contract", sa.analyze, large_sol, "large.sol", use_slither=False, use_ast=False)

# ═══════════════════════════════════════════════════════════════
# 3. REAL CONTRACT — DeFiHackLabs exploits
# ═══════════════════════════════════════════════════════════════
print("\n=== 3. REAL EXPLOITS (DeFiHackLabs) ===")

defi_dir = Path("src/audit/DeFiHackLabs/src/test")
real_files = sorted(defi_dir.glob("**/*.sol"))[:20]

sa_batch = StaticAnalyzer()
for sol_path in real_files[:5]:
    src = sol_path.read_text(errors="ignore")
    loc = len(src.split("\n"))
    name = sol_path.name[:30]
    bench(f"real: {name} ({loc}L)", sa_batch.analyze, src, sol_path.name, use_slither=False, use_ast=False, runs=1)

# Batch: scan 20 files
def scan_batch(files):
    total_findings = 0
    scanner = StaticAnalyzer()
    for f in files:
        src = f.read_text(errors="ignore")
        result = scanner.analyze(src, f.name, use_slither=False, use_ast=False)
        total_findings += len(result.findings)
    return total_findings

n_findings = bench("batch: 20 real exploits", scan_batch, real_files, runs=1)
results["batch: 20 real exploits"]["n_files"] = len(real_files)
results["batch: 20 real exploits"]["n_findings"] = n_findings
total_loc = sum(len(f.read_text(errors="ignore").split("\n")) for f in real_files)
results["batch: 20 real exploits"]["total_loc"] = total_loc
results["batch: 20 real exploits"]["loc_per_sec"] = round(total_loc / results["batch: 20 real exploits"]["mean_s"], 0)

# ALL 727 files
all_files = sorted(defi_dir.glob("**/*.sol"))
print(f"\n  Scanning ALL {len(all_files)} DeFiHackLabs files...")
n_all = bench(f"batch: ALL {len(all_files)} exploits", scan_batch, all_files, runs=1)
all_loc = sum(len(f.read_text(errors="ignore").split("\n")) for f in all_files)
results[f"batch: ALL {len(all_files)} exploits"]["n_files"] = len(all_files)
results[f"batch: ALL {len(all_files)} exploits"]["n_findings"] = n_all
results[f"batch: ALL {len(all_files)} exploits"]["total_loc"] = all_loc
results[f"batch: ALL {len(all_files)} exploits"]["loc_per_sec"] = round(all_loc / results[f"batch: ALL {len(all_files)} exploits"]["mean_s"], 0)

# ═══════════════════════════════════════════════════════════════
# 4. EIP-7702 DETECTOR
# ═══════════════════════════════════════════════════════════════
print("\n=== 4. EIP-7702 DETECTOR ===")

from src.eip7702_detector import EIP7702Detector

eip_det = EIP7702Detector()
eip_sol = """
pragma solidity ^0.8.0;
contract Wallet {
    function execute(address to, bytes calldata data) external {
        require(tx.origin == msg.sender, "not EOA");
        (bool ok,) = to.call(data);
        require(ok);
    }
    function isEOA(address a) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(a) }
        return size == 0;
    }
}
"""
bench("eip7702: single contract", eip_det.check, eip_sol, "wallet.sol")
bench("eip7702: 1600-line contract", eip_det.check, large_sol, "large.sol")

# ═══════════════════════════════════════════════════════════════
# 5. ML PIPELINE — feature scoring
# ═══════════════════════════════════════════════════════════════
print("\n=== 5. ML ENSEMBLE (scoring) ===")

import numpy as np
from src.model_trainer import ModelTrainer

trainer = ModelTrainer(data_dir=Path("data/baseline"))

records = []
for line in open("data/baseline/features_20260523.jsonl"):
    if line.strip():
        records.append(json.loads(line))

all_keys = sorted({k for r in records for k in r.get("features", {})})
X = np.zeros((len(records), len(all_keys)))
y = np.zeros(len(records), dtype=int)
for i, rec in enumerate(records):
    fd = rec.get("features", {})
    for j, k in enumerate(all_keys):
        X[i, j] = fd.get(k, 0.0)
    y[i] = 1 if rec["label"] == "exploit" else 0

trainer.feature_names = all_keys
trainer.train_isolation_forest(X[y == 0])
trainer.train_xgboost(X, y)
trainer.train_threshold(X, y)

def score_single():
    return float(trainer.predict_proba_ensemble(X[0:1])[0])

def score_batch_219():
    return trainer.predict_proba_ensemble(X)

bench("ml: score 1 transaction", score_single, runs=100)
bench("ml: score 219 transactions", score_batch_219, runs=10)

# Simulate 10K transactions
X_10k = np.tile(X, (46, 1))[:10000]
def score_10k():
    return trainer.predict_proba_ensemble(X_10k)
bench("ml: score 10K transactions", score_10k, runs=3)

# ═══════════════════════════════════════════════════════════════
# 6. OWASP MAPPING
# ═══════════════════════════════════════════════════════════════
print("\n=== 6. OWASP 2026 MAPPING ===")

from src.owasp_2026 import annotate_findings, coverage_report

fake_findings = [{"check": "readonly_reentrancy", "severity": "HIGH"}] * 500
bench("owasp: annotate 500 findings", annotate_findings, fake_findings, runs=10)
bench("owasp: coverage report", coverage_report, fake_findings, runs=10)

# ═══════════════════════════════════════════════════════════════
# 7. EVM TRACER — parse trace fixtures
# ═══════════════════════════════════════════════════════════════
print("\n=== 7. EVM TRACER (parse traces) ===")

from src.evm_tracer import decode_trace

trace_dir = Path("tests/fixtures/traces")
trace_files = sorted(trace_dir.glob("*.json"))

for tf in trace_files[:5]:
    raw = json.loads(tf.read_text())
    name = tf.stem[:35]
    bench(f"trace: {name}", decode_trace, raw, runs=3)

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("  CHAINEDR PERFORMANCE BENCHMARK SUMMARY")
print("=" * 70)

print(f"\n  {'Benchmark':45s} {'Time':>10s} {'Memory':>10s}")
print(f"  {'─'*45} {'─'*10} {'─'*10}")
for name, r in results.items():
    t = f"{r['mean_s']:.3f}s"
    m = f"{r['peak_mb']:.1f}MB"
    extra = ""
    if "loc_per_sec" in r:
        extra = f"  ({r['loc_per_sec']:.0f} LOC/s, {r['n_findings']} findings)"
    print(f"  {name:45s} {t:>10s} {m:>10s}{extra}")

print(f"\n{'=' * 70}")

with open("data/performance_benchmark.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"  Saved to data/performance_benchmark.json")
