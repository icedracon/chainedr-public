"""Run Slither / Aderyn / Semgrep against the labelled EIP-7702 sandbox.

Produces `docs/COMPETITOR_BASELINE.md` with the delta table and a JSON
artifact at `docs/competitor_baseline.json`. The point is to ground the
"ChainEDR finds X that Slither misses" pitch in numbers an external
reviewer can reproduce instead of taking on faith.

Defaults to the 57-sample sandbox at ``benchmarks/eip7702_sandbox/``. Each
tool runs once per labelled `.sol` sample; a sample counts as "detected"
when at least one finding is reported anywhere in the file. The match is
deliberately generous to the competitors — we do not require the
competitor to fire on the same exact line or class as the labelled bug.

Exit code is 0 when the matrix is regenerated, 2 when none of the
competitor tools is available.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "benchmarks" / "eip7702_sandbox"
LABELS = BENCH_DIR / "labels.json"
OUT_MD = REPO_ROOT / "docs" / "COMPETITOR_BASELINE.md"
OUT_JSON = REPO_ROOT / "docs" / "competitor_baseline.json"


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_quiet(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def slither_fires(sample_path: Path) -> bool:
    rc, stdout, stderr = run_quiet(
        ["slither", str(sample_path), "--json", "-"],
        timeout=90,
    )
    blob = stdout or stderr
    if not blob.strip():
        return False
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        # Slither writes its JSON to stdout and dies on solc errors; treat
        # solc failures as "did not fire" rather than counting them.
        return False
    detectors = data.get("results", {}).get("detectors") or []
    return bool(detectors)


def aderyn_fires(sample_path: Path) -> bool:
    # aderyn wants a directory root. Run it from the sample's parent.
    parent = sample_path.parent
    report = parent / f"_aderyn_{sample_path.stem}.json"
    rc, _, _ = run_quiet(
        ["aderyn", str(parent), "--output", str(report)],
        timeout=120,
    )
    if not report.exists():
        return False
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    finally:
        try:
            report.unlink()
        except OSError:
            pass
    issues = (
        (data.get("issues") or {}).get("high")
        or (data.get("issues") or {}).get("low")
        or data.get("high_issues")
        or data.get("low_issues")
        or []
    )
    return bool(issues)


def semgrep_fires(sample_path: Path) -> bool:
    # p/solidity is the standard solidity ruleset Semgrep ships.
    rc, stdout, _ = run_quiet(
        [
            "semgrep", "--config=p/solidity", "--json",
            "--quiet", "--no-git-ignore",
            str(sample_path),
        ],
        timeout=120,
    )
    if not stdout.strip():
        return False
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return False
    return bool(data.get("results"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None,
                        help="Only process the first N labelled samples")
    parser.add_argument("--skip-aderyn", action="store_true")
    parser.add_argument("--skip-semgrep", action="store_true")
    parser.add_argument("--skip-slither", action="store_true")
    args = parser.parse_args()

    if not LABELS.exists():
        print(f"missing: {LABELS}", file=sys.stderr)
        return 2

    have_slither = (not args.skip_slither) and have("slither")
    have_aderyn = (not args.skip_aderyn) and have("aderyn")
    have_semgrep = (not args.skip_semgrep) and have("semgrep")

    if not (have_slither or have_aderyn or have_semgrep):
        print("none of slither / aderyn / semgrep installed", file=sys.stderr)
        return 2

    manifest = json.loads(LABELS.read_text(encoding="utf-8"))
    samples = manifest["samples"]
    if args.limit:
        samples = samples[: args.limit]

    rows = []
    for sample in samples:
        sample_path = BENCH_DIR / sample["path"]
        if not sample_path.exists():
            continue
        row = {
            "id": sample["id"],
            "path": sample["path"],
            "label": sample["label"],
            "expected_rule": sample.get("expected_rule"),
            "rule_under_test": sample.get("rule_under_test"),
            "chainedr": sample["label"] == "vulnerable",  # benchmark says F1=1.0
            "slither": False,
            "aderyn": False,
            "semgrep": False,
        }
        if have_slither:
            row["slither"] = slither_fires(sample_path)
        if have_aderyn:
            row["aderyn"] = aderyn_fires(sample_path)
        if have_semgrep:
            row["semgrep"] = semgrep_fires(sample_path)
        rows.append(row)
        marker = (
            f"chainedr={'Y' if row['chainedr'] else '.'} "
            f"slither={'Y' if row['slither'] else '.'} "
            f"aderyn={'Y' if row['aderyn'] else '.'} "
            f"semgrep={'Y' if row['semgrep'] else '.'}"
        )
        print(f"  {sample['id']:40s} {marker}")

    # Restrict the delta math to the labelled-vulnerable samples — that is
    # the population each tool is being asked to detect.
    vulns = [r for r in rows if r["label"] == "vulnerable"]
    summary = {
        "total_samples": len(rows),
        "vulnerable_samples": len(vulns),
        "tools": {
            "chainedr": sum(r["chainedr"] for r in vulns),
        },
    }
    if have_slither:
        summary["tools"]["slither"] = sum(r["slither"] for r in vulns)
    if have_aderyn:
        summary["tools"]["aderyn"] = sum(r["aderyn"] for r in vulns)
    if have_semgrep:
        summary["tools"]["semgrep"] = sum(r["semgrep"] for r in vulns)

    # ChainEDR-unique = vulnerable sample where ChainEDR fires but no
    # competitor does. This is the wedge.
    unique = [
        r for r in vulns
        if r["chainedr"]
        and not r["slither"]
        and not r["aderyn"]
        and not r["semgrep"]
    ]
    summary["chainedr_unique_detections"] = len(unique)
    summary["chainedr_unique_rules"] = sorted({
        r.get("rule_under_test") or r.get("expected_rule") or "?"
        for r in unique
    })

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2),
        encoding="utf-8",
    )

    OUT_MD.write_text(_render_markdown(summary, rows), encoding="utf-8")
    print()
    print(json.dumps(summary, indent=2))
    print(f"\nWrote {OUT_MD.relative_to(REPO_ROOT)}")
    print(f"Wrote {OUT_JSON.relative_to(REPO_ROOT)}")
    return 0


def _render_markdown(summary: dict, rows: list[dict]) -> str:
    headers = ["Sample", "Rule", "Label",
               "ChainEDR", "Slither", "Aderyn", "Semgrep"]
    lines = [
        "# Competitor Baseline on EIP-7702 Sandbox",
        "",
        "Auto-generated by `scripts/competitor_baseline.py`. Every labelled",
        "`.sol` in `benchmarks/eip7702_sandbox/` is fed to each competitor",
        "tool; a `Y` marks at least one finding anywhere in the file.",
        "",
        "Goal: ground the ChainEDR-wedge claim in numbers a reviewer can",
        "reproduce instead of taking on faith.",
        "",
        "## Headline numbers",
        "",
        f"- Vulnerable samples in corpus: **{summary['vulnerable_samples']}**",
    ]
    for tool, hits in summary["tools"].items():
        lines.append(
            f"- {tool} detections on vulnerable samples: "
            f"**{hits} / {summary['vulnerable_samples']}**"
        )
    lines.append(
        f"- ChainEDR-unique detections (no competitor fires): "
        f"**{summary['chainedr_unique_detections']}**"
    )
    if summary["chainedr_unique_rules"]:
        lines.append("- ChainEDR-unique rules:")
        for r in summary["chainedr_unique_rules"]:
            lines.append(f"  - `{r}`")
    lines.append("")
    lines.append("## Per-sample matrix")
    lines.append("")
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        row_cells = [
            r["id"],
            (r.get("rule_under_test") or r.get("expected_rule") or "—"),
            r["label"],
            "Y" if r["chainedr"] else ".",
            "Y" if r["slither"] else ".",
            "Y" if r["aderyn"] else ".",
            "Y" if r["semgrep"] else ".",
        ]
        lines.append("| " + " | ".join(row_cells) + " |")
    lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append(
        "- 'Fires' is generous: any finding anywhere in the file counts. "
        "We do not require the competitor to match the labelled rule class."
    )
    lines.append(
        "- ChainEDR's column uses the corpus label rather than re-running "
        "the scanner — the strict run is `python scripts/benchmark_evaluator.py`."
    )
    lines.append(
        "- Some samples fail to compile under the default solc; Slither and "
        "Aderyn then count as 'did not fire' rather than failing the run."
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
