#!/usr/bin/env python3
"""
One-command reproduction of every headline ChainEDR metric.

    python scripts/reproduce.py            # print + write results/reproduce_report.md
    python scripts/reproduce.py --json results/metrics.json

Regenerates:
  1. Controlled benchmark (EIP7702-Bench): TP/FP/TN/FN, precision/recall/F1,
     specificity, Wilson 95% CI, and a confusion matrix.
  2. Held-out validation summary (test_targets/holdout/_results/*.json) if present.
  3. On-chain bounty-target summary (test_targets/onchain/_results/*.json) if present.

Paper-grade: deterministic, no network, single source of truth for the numbers
quoted in REALITY_CHECK.md and the paper.
"""
import argparse
import glob
import json
import math
import os
import subprocess
import sys

try:  # keep emoji/em-dash output safe on Windows cp1252 consoles
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wilson(p_hat, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    denom = 1 + z * z / n
    center = (p_hat + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def run_benchmark():
    out = os.path.join(ROOT, "results", "benchmark_eval.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "benchmark_evaluator.py"),
                    "-o", out], cwd=ROOT, capture_output=True)
    if not os.path.exists(out):
        return None
    return json.load(open(out))


def rule_coverage(bench, target=10):
    """Per-rule sample counts from per_detector, so the n>=10-per-rule growth
    target is measurable and honest rather than asserted."""
    pd = (bench or {}).get("per_detector") or {}
    counts = {}
    for rule, d in pd.items():
        n = len(d.get("samples", [])) or (d.get("tp", 0) + d.get("fp", 0)
                                          + d.get("tn", 0) + d.get("fn", 0))
        counts[rule] = n
    if not counts:
        return None
    vals = sorted(counts.values())
    below = sum(1 for v in vals if v < target)
    median = vals[len(vals) // 2]
    return {"rules": len(counts), "min": vals[0], "median": median, "max": vals[-1],
            "target": target, "rules_below_target": below, "per_rule": counts}


def summarize_triage(verdicts_json):
    """Frozen-audited bucket: read a triage_verdicts.json (hand-classified) and
    report TP/FP/UNCERTAIN + precision + FP rate. Distinct from the benchmark."""
    if not os.path.exists(verdicts_json):
        return None
    try:
        rows = json.load(open(verdicts_json))
    except Exception:
        return None
    c = {"TP": 0, "FP": 0, "UNCERTAIN": 0, "UNCLASSIFIED": 0}
    for r in rows:
        v = str(r.get("verdict", "")).upper()
        c[v] = c.get(v, 0) + 1
    tot = sum(c.values())
    tp, fp, un = c["TP"], c["FP"], c["UNCERTAIN"]
    return {"total": tot, "tp": tp, "fp": fp, "uncertain": un,
            "unclassified": c["UNCLASSIFIED"],
            "precision_strict": _safe(tp, tp + fp),
            "fp_rate": _safe(fp, tot)}


def summarize_results(folder):
    files = glob.glob(os.path.join(folder, "*.json"))
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    fam = {"eip7702": 0, "generic": 0}
    n = 0
    targets = 0
    for f in files:
        base = os.path.basename(f)
        if base in ("triage.py", "triage_verdicts.json") or base.startswith("_"):
            continue
        try:
            data = json.load(open(f))
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        targets += 1
        for x in data:
            n += 1
            s = str(x.get("severity", "INFO")).upper()
            sev[s] = sev.get(s, 0) + 1
            fam["eip7702" if str(x.get("check", "")).startswith("AA7702") else "generic"] += 1
    return {"targets": targets, "findings": n, "severity": sev, "family": fam}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(ROOT, "results", "metrics.json"))
    ap.add_argument("--md", default=os.path.join(ROOT, "results", "reproduce_report.md"))
    args = ap.parse_args()

    bench = run_benchmark()
    metrics = {}
    lines = ["# ChainEDR — Reproduced Metrics", ""]

    if bench:
        o = bench.get("overall", bench)
        tp, fp, tn, fn = o.get("tp", 0), o.get("fp", 0), o.get("tn", 0), o.get("fn", 0)
        prec, rec, f1 = o.get("precision", 0), o.get("recall", 0), o.get("f1", 0)
        spec = o.get("specificity", _safe(tn, tn + fp))
        lo_p, hi_p = wilson(prec, tp + fp + fn)
        lo_r, hi_r = wilson(rec, tp + fn)
        metrics["benchmark"] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "f1": f1, "specificity": spec,
            "precision_ci95": [round(lo_p, 3), round(hi_p, 3)],
            "recall_ci95": [round(lo_r, 3), round(hi_r, 3)],
        }
        lines += [
            "## 1. Controlled benchmark (EIP7702-Bench)", "",
            "```", "Confusion matrix",
            f"               predicted+   predicted-",
            f"  actual+        TP={tp:<3}        FN={fn:<3}",
            f"  actual-        FP={fp:<3}        TN={tn:<3}",
            "```",
            f"- precision = **{prec:.3f}**  (Wilson 95% CI [{lo_p:.3f}, {hi_p:.3f}])",
            f"- recall    = **{rec:.3f}**  (Wilson 95% CI [{lo_r:.3f}, {hi_r:.3f}])",
            f"- F1        = **{f1:.3f}**",
            f"- specificity = **{spec:.3f}**",
            "",
            "> CI width is wide because the corpus has ~1 sample per rule; expanding to "
            "n>=10 per rule (Tier 4) narrows it. This number is corpus-scoped, not a "
            "production-precision claim.", "",
        ]
        cov = rule_coverage(bench)
        if cov:
            metrics["benchmark"]["coverage"] = {k: v for k, v in cov.items()
                                                if k != "per_rule"}
            lines += [
                f"- per-rule coverage: **{cov['rules']} rules**, samples/rule "
                f"min={cov['min']} median={cov['median']} max={cov['max']}",
                f"- **{cov['rules_below_target']}/{cov['rules']} rules below the "
                f"n>={cov['target']} target** (corpus-growth gap, tracked honestly)",
                "",
                "> Growth must come from INDEPENDENT samples (real audited code / public "
                "bug reports), not self-authored variants — padding a benchmark the "
                "detectors are tuned against would inflate, not validate.", "",
            ]
    else:
        lines += ["## 1. Controlled benchmark", "", "_evaluator did not produce output_", ""]

    # ── Frozen audited targets (hand-triaged precision, distinct bucket) ───────
    frozen = summarize_triage(os.path.join(
        ROOT, "test_targets", "reality_check", "_results_v2", "triage_verdicts.json"))
    if frozen:
        metrics["frozen_audited"] = frozen
        lines += [
            "## 2. Frozen audited targets (hand-triaged)", "",
            f"- findings: **{frozen['total']}** — TP={frozen['tp']} "
            f"FP={frozen['fp']} UNCERTAIN={frozen['uncertain']}"
            + (f" UNCLASSIFIED={frozen['unclassified']}" if frozen['unclassified'] else ""),
            f"- strict precision (TP/(TP+FP)) = **{frozen['precision_strict']:.1%}**, "
            f"FP rate = **{frozen['fp_rate']:.1%}**",
            "",
            "> Professionally-audited AA/7702 wallets — expected real bugs ~0; this "
            "measures FP discipline, NOT production precision. UNCERTAIN = real pattern, "
            "design-dependent (each individually justified in triage_verdicts.json).", "",
        ]

    for title, folder, key in [
        ("3. Held-out validation (held-out bounty codebases)", "test_targets/holdout/_results", "holdout"),
        ("4. On-chain bounty targets (deployed)", "test_targets/onchain/_results", "onchain"),
    ]:
        path = os.path.join(ROOT, folder)
        if os.path.isdir(path):
            s = summarize_results(path)
            metrics[key] = s
            sv = s["severity"]
            lines += [
                f"## {title}", "",
                f"- targets scanned: **{s['targets']}**, findings: **{s['findings']}**",
                f"- severity: CRIT={sv['CRITICAL']} HIGH={sv['HIGH']} MED={sv['MEDIUM']} LOW={sv['LOW']}",
                f"- family: EIP-7702={s['family']['eip7702']}, generic={s['family']['generic']}", "",
            ]
        else:
            lines += [f"## {title}", "", "_no local results (clone + scan to regenerate)_", ""]

    lines += ["---", "Full triage + verdicts: `REALITY_CHECK.md`."]

    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    json.dump(metrics, open(args.json, "w"), indent=2)
    open(args.md, "w", encoding="utf-8").write("\n".join(lines))
    print("\n".join(lines))
    print(f"\n[wrote {os.path.relpath(args.md, ROOT)} and {os.path.relpath(args.json, ROOT)}]")
    return 0


def _safe(a, b):
    return a / b if b else 0.0


if __name__ == "__main__":
    sys.exit(main())
