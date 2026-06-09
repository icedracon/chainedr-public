"""Evaluate ChainEDR on the external (non-self-written) benchmark.

The labelled `eip7702_sandbox` and held-out `holdout_v1` corpora are
authored by the ChainEDR maintainers — labelled F1=1.00 on those is
necessarily a regression test, not a precision claim. `external_v1` is
the honest precision corpus: every sample is a production .sol file
pulled live from an upstream repository, with the source URL recorded
in labels.json.

The scoring rule is intentionally simple. For each sample, the analyzer
fires zero or more AA7702-* / AA7562-* rules. The label records what
the maintainers expected to fire and the triage verdict. A
sample scores as:

  CORRECT  — fires match expected fires exactly, and the verdict is
             not FP.
  DRIFT    — fires differ from expected (either a new finding appeared
             or an expected finding disappeared). Surfaces real
             regressions / improvements.
  REGRESS  — the verdict for this sample is FP, meaning the analyzer
             surfaced a known FP that has not yet been fixed.

The headline metric is **precision_on_aa7702_fires**: the share of
AA7702-* fires across the corpus whose verdict is TP or ARCH (i.e.,
useful for a reviewer), excluding rules listed in
``scoring.exclude_rules``.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import types
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


def _bootstrap_chainedr() -> None:
    sys.path.insert(0, str(REPO))
    src_path = REPO / "src"
    mod = types.ModuleType("chainedr")
    mod.__path__ = [str(src_path)]
    sys.modules["chainedr"] = mod


def _scan(target: Path) -> list[dict]:
    import argparse as _ap
    import chainedr.cli as cli  # type: ignore[import-not-found]

    out_json = target.parent / f"_scan_{target.stem}.json"
    ns = _ap.Namespace(
        target=str(target),
        no_external=True,
        no_ast=False,
        deep=False,
        extended=False,
        mythril=False,
        external_timeout=30,
        ignore=[],
        min_severity="LOW",
        format="compact",
        sarif=None,
        json_out=str(out_json),
        fail_on=None,
        profile="default",
        output_dir=None,
        ai_triage=False,
        prove=False,
        prove_on_finding=[],
        prove_out=None,
    )
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        cli.cmd_scan(ns)
    finally:
        sys.stdout, sys.stderr = saved
    try:
        data = json.loads(out_json.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    finally:
        try:
            out_json.unlink()
        except OSError:
            pass
    return data.get("findings", []) if isinstance(data, dict) else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        default=str(REPO / "benchmarks" / "external_v1"),
    )
    args = parser.parse_args()

    _bootstrap_chainedr()

    corpus = Path(args.corpus)
    labels = json.loads((corpus / "labels.json").read_text(encoding="utf-8"))
    exclude_rules = set(
        (labels.get("scoring") or {}).get("exclude_rules") or []
    )

    rows = []
    fires_total = 0
    fires_useful = 0  # TP + ARCH
    drift_count = 0
    correct_count = 0
    regress_count = 0
    for sample in labels["samples"]:
        path = corpus / sample["path"]
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            continue
        findings = _scan(path)
        observed_rules = sorted({
            (f.get("rule_id") or f.get("check_id") or "?")
            for f in findings
            if (f.get("rule_id") or f.get("check_id")) not in exclude_rules
        })
        expected = sorted(sample.get("fires") or [])
        verdict = sample.get("verdict", "?")

        if observed_rules == expected:
            outcome = "CORRECT"
            correct_count += 1
        else:
            outcome = "DRIFT"
            drift_count += 1

        if verdict == "FP":
            regress_count += 1
            outcome = "REGRESS"

        for rule in observed_rules:
            fires_total += 1
            if verdict in {"TP", "ARCH"}:
                fires_useful += 1

        rows.append({
            "id": sample["id"],
            "path": sample["path"],
            "source_url": sample["source_url"],
            "expected_fires": expected,
            "observed_fires": observed_rules,
            "verdict": verdict,
            "outcome": outcome,
            "rationale": sample.get("rationale", ""),
        })

    precision = (
        fires_useful / fires_total if fires_total > 0 else 1.0
    )

    summary = {
        "corpus": labels["name"],
        "version": labels["version"],
        "samples": len(labels["samples"]),
        "scored_samples": len(rows),
        "correct": correct_count,
        "drift": drift_count,
        "regress": regress_count,
        "aa7702_fires_total": fires_total,
        "aa7702_fires_useful": fires_useful,
        "precision_on_aa7702_fires": round(precision, 4),
    }

    out_md = REPO / "docs" / "EXTERNAL_BENCHMARK.md"
    out_json = REPO / "docs" / "external_benchmark.json"
    out_json.write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2),
        encoding="utf-8",
    )
    out_md.write_text(_render_md(summary, rows), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nWrote {out_md.relative_to(REPO)}")
    print(f"Wrote {out_json.relative_to(REPO)}")
    return 0


def _render_md(summary: dict, rows: list[dict]) -> str:
    lines = [
        "# ChainEDR External Benchmark Results",
        "",
        "Auto-generated by `scripts/external_evaluator.py` against",
        "`benchmarks/external_v1/`. Every sample is a production .sol",
        "file pulled live from an upstream repository — none was authored",
        "by the ChainEDR maintainers.",
        "",
        "## Headline",
        "",
        f"- Corpus: **{summary['corpus']} v{summary['version']}**",
        f"- Samples: **{summary['samples']}**",
        f"- CORRECT / DRIFT / REGRESS: "
        f"**{summary['correct']} / {summary['drift']} / "
        f"{summary['regress']}**",
        f"- Total AA7702-\\* / AA7562-\\* fires on the corpus: "
        f"**{summary['aa7702_fires_total']}**",
        f"- Useful fires (TP + ARCH): **{summary['aa7702_fires_useful']}**",
        f"- **Precision on AA fires: "
        f"{summary['precision_on_aa7702_fires'] * 100:.1f}%**",
        "",
        "## Per-sample",
        "",
        "| Sample | Source | Expected | Observed | Verdict | Outcome |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        src_short = r["source_url"].split("/")[-1]
        lines.append(
            f"| `{r['id']}` | "
            f"[`{src_short}`]({r['source_url']}) | "
            f"{', '.join(r['expected_fires']) or '—'} | "
            f"{', '.join(r['observed_fires']) or '—'} | "
            f"**{r['verdict']}** | "
            f"**{r['outcome']}** |"
        )
    lines.append("")
    lines.append("## Rationale per sample")
    lines.append("")
    for r in rows:
        lines.append(
            f"- `{r['id']}` ({r['verdict']} / {r['outcome']}): "
            f"{r['rationale']}"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
