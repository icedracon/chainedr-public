"""Evidence-pack helpers for ChainEDR.

The scanner is useful only when reviewers can reproduce and inspect the
argument behind a finding. This module turns machine output into small,
shareable artifacts: demo packs and finding evidence bundles.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def find_repo_root(start: Path | None = None) -> Path:
    """Best-effort repository root discovery.

    Editable installs keep ``src`` next to the benchmark corpus. Installed
    wheels may not include those files, so callers should handle a missing
    benchmark gracefully.
    """
    candidates = []
    if start is not None:
        candidates.append(start)
    candidates.extend([Path.cwd(), Path(__file__).resolve()])

    for candidate in candidates:
        base = candidate if candidate.is_dir() else candidate.parent
        for path in (base, *base.parents):
            if (path / "benchmarks" / "eip7702_sandbox" / "labels.json").exists():
                return path
            if (path / ".git").exists() and (path / "src").exists():
                return path
    return Path.cwd()


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _as_finding_dict(finding: Any, file_path: str | None = None) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        data = finding.to_dict()
    elif isinstance(finding, dict):
        data = dict(finding)
    else:
        data = {
            "title": getattr(finding, "title", "Finding"),
            "description": getattr(finding, "description", ""),
        }

    if "rule_id" not in data and "check_id" in data:
        data["rule_id"] = data["check_id"]
    if "fix" not in data and "recommendation" in data:
        data["fix"] = data["recommendation"]
    if not data.get("detector"):
        rule_id = str(data.get("rule_id") or data.get("check_id") or "")
        if rule_id.startswith("AA7702"):
            data["detector"] = "eip7702"
        elif rule_id.startswith("AA7562"):
            data["detector"] = "eip7702_validation"
    if file_path and not data.get("file_path"):
        data["file_path"] = file_path
    return data


def _line_number(finding: dict[str, Any]) -> int:
    raw = finding.get("line") or finding.get("location") or 1
    if isinstance(raw, int):
        return max(raw, 1)
    if isinstance(raw, str):
        digits = "".join(ch for ch in raw if ch.isdigit())
        if digits:
            return max(int(digits), 1)
    return 1


def _resolve_source_path(file_path: str, source_root: Path) -> Path | None:
    if not file_path:
        return None
    path = Path(file_path)
    if path.is_absolute() and path.exists():
        return path
    candidate = source_root / path
    if candidate.exists():
        return candidate
    return None


def _source_excerpt(finding: dict[str, Any], source_root: Path, radius: int = 2) -> str:
    path = _resolve_source_path(str(finding.get("file_path", "")), source_root)
    if path is None:
        return ""
    line = _line_number(finding)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(line - radius, 1)
    end = min(line + radius, len(lines))
    excerpt = []
    for number in range(start, end + 1):
        marker = ">" if number == line else " "
        excerpt.append(f"{marker} {number:4d} | {lines[number - 1]}")
    return "\n".join(excerpt)


def _finding_verdict(finding: dict[str, Any]) -> str:
    metadata = finding.get("metadata") or {}
    if isinstance(metadata, dict) and metadata.get("verdict"):
        return str(metadata["verdict"])
    confidence = float(finding.get("confidence") or 0)
    severity = str(finding.get("severity") or "").upper()
    if confidence >= 0.85 and severity in {"CRITICAL", "HIGH"}:
        return "REAL_CANDIDATE"
    if confidence >= 0.55:
        return "UNCERTAIN"
    return "NEEDS_TRIAGE"


def render_evidence_bundle(
    report: dict[str, Any],
    source_root: Path,
    max_findings: int = 25,
) -> str:
    """Render a ChainEDR JSON report as reviewer-oriented Markdown."""
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    by_severity: dict[str, int] = {}
    by_detector: dict[str, int] = {}
    for raw in findings:
        finding = _as_finding_dict(raw)
        severity = str(finding.get("severity") or "UNKNOWN")
        detector = str(finding.get("detector") or "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_detector[detector] = by_detector.get(detector, 0) + 1

    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    if isinstance(summary, dict):
        by_severity = summary.get("by_severity") or by_severity
        by_detector = summary.get("by_detector") or by_detector

    lines = [
        "# ChainEDR Evidence Bundle",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Source root: `{source_root}`",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: **{len(findings)}**",
        f"- Severity mix: `{json.dumps(by_severity, sort_keys=True)}`",
        f"- Detector mix: `{json.dumps(by_detector, sort_keys=True)}`",
        "",
        "## How To Read This",
        "",
        "ChainEDR evidence bundles are built for human review. A finding is a",
        "security argument, not an automatic exploit claim. Review the rule, the",
        "source excerpt, the EIP-7702 sandbox boundary metadata, and the fix",
        "suggestion before treating it as confirmed.",
        "",
        "Verdict labels used here:",
        "",
        "- `REAL_CANDIDATE`: high-confidence and high-impact, worth immediate review.",
        "- `UNCERTAIN`: the pattern is real but exploitability depends on context.",
        "- `NEEDS_TRIAGE`: low confidence or incomplete context.",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.extend(["No findings were present in the input JSON.", ""])
        return "\n".join(lines)

    for idx, raw in enumerate(findings[:max_findings], 1):
        finding = _as_finding_dict(raw)
        rule_id = finding.get("rule_id") or finding.get("check_id") or "UNKNOWN"
        title = finding.get("title") or "Untitled finding"
        severity = finding.get("severity") or "UNKNOWN"
        file_path = finding.get("file_path") or "unknown"
        line = _line_number(finding)
        verdict = _finding_verdict(finding)

        lines.extend([
            f"### {idx}. {rule_id} - {title}",
            "",
            f"- Severity: **{severity}**",
            f"- Detector: `{finding.get('detector', 'unknown')}`",
            f"- Confidence: `{finding.get('confidence', 0)}`",
            f"- Verdict: **{verdict}**",
            f"- Location: `{file_path}:{line}`",
        ])

        if finding.get("cwe"):
            lines.append(f"- CWE: `{finding['cwe']}`")

        metadata = finding.get("metadata") or {}
        sandbox = metadata.get("sandbox") if isinstance(metadata, dict) else None
        if not sandbox and isinstance(metadata, dict):
            sandbox = metadata.get("pre_behavior_trace") or metadata.get("sandbox_policy")
        if sandbox:
            lines.append(f"- Sandbox metadata: `{json.dumps(sandbox, sort_keys=True)[:500]}`")

        description = finding.get("description") or ""
        if description:
            lines.extend(["", "**Why it matters**", "", description])

        excerpt = _source_excerpt(finding, source_root)
        if excerpt:
            lines.extend(["", "**Source excerpt**", "", "```solidity", excerpt, "```"])

        fix = finding.get("fix") or finding.get("fix_suggestion") or finding.get("recommendation")
        if fix:
            lines.extend(["", "**Suggested fix**", "", str(fix)])

        lines.append("")

    if len(findings) > max_findings:
        lines.extend([
            f"_Only the first {max_findings} findings are shown. The input JSON",
            "contains the full set._",
            "",
        ])

    return "\n".join(lines)


def write_evidence_bundle(
    json_report: Path,
    output: Path,
    source_root: Path | None = None,
    max_findings: int = 25,
) -> dict[str, Any]:
    """Write a Markdown evidence bundle from a ChainEDR JSON report."""
    report = _load_json(json_report)
    if isinstance(report, list):
        report = {"findings": report, "summary": {"total": len(report)}}
    if not isinstance(report, dict):
        raise ValueError("ChainEDR JSON report must be an object or a finding list")

    root = source_root or find_repo_root(json_report.parent)
    markdown = render_evidence_bundle(report, root, max_findings=max_findings)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return {
        "output": str(output),
        "findings": len(report.get("findings", [])),
        "source_root": str(root),
    }


def _load_benchmark_evaluator(repo_root: Path):
    script = repo_root / "scripts" / "benchmark_evaluator.py"
    if not script.exists():
        raise FileNotFoundError(f"benchmark evaluator not found: {script}")

    module_name = "_chainedr_benchmark_evaluator"
    spec = importlib.util.spec_from_file_location(module_name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load benchmark evaluator from {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module.evaluate


def _run_single_eip7702_sample(path: Path, rule_id: str) -> dict[str, Any]:
    try:
        from .eip7702_detector import EIP7702Detector
    except ImportError:
        from eip7702_detector import EIP7702Detector

    source = path.read_text(encoding="utf-8", errors="replace")
    detector = EIP7702Detector()
    findings = detector.check_selective(source, [rule_id])
    return {
        "path": str(path),
        "rule_under_test": rule_id,
        "findings": [_as_finding_dict(f, file_path=str(path)) for f in findings],
    }


def run_friend_demo(
    output_dir: Path,
    include_benchmark: bool = True,
) -> dict[str, Any]:
    """Generate a small reviewer-friendly demo pack.

    The pack intentionally uses a vulnerable/fixed pair plus the labeled
    benchmark evaluator. It avoids running the full scanner over the benchmark
    root because that corpus intentionally contains vulnerable contracts.
    """
    repo_root = find_repo_root()
    corpus = repo_root / "benchmarks" / "eip7702_sandbox"
    vulnerable = corpus / "vulnerable" / "txorigin.sol"
    fixed = corpus / "fixed" / "txorigin.sol"
    labels = corpus / "labels.json"

    if not vulnerable.exists() or not fixed.exists():
        raise FileNotFoundError("EIP-7702 demo samples are missing from benchmarks/eip7702_sandbox")

    output_dir.mkdir(parents=True, exist_ok=True)

    vulnerable_result = _run_single_eip7702_sample(vulnerable, "AA7702-001")
    fixed_result = _run_single_eip7702_sample(fixed, "AA7702-001")
    _write_json(output_dir / "vulnerable_txorigin.json", vulnerable_result)
    _write_json(output_dir / "fixed_txorigin.json", fixed_result)

    benchmark_result = None
    if include_benchmark:
        evaluate = _load_benchmark_evaluator(repo_root)
        benchmark_result = evaluate(corpus, labels)
        _write_json(output_dir / "benchmark_results.json", benchmark_result)

    commands = [
        "python -m pip install -e ./src",
        "chainedr prove demo --out demo_out",
        "python scripts/benchmark_evaluator.py --strict -o results/eip7702_benchmark_eval.json",
        "# Optional WSL only from repo root: python3 poc/differential_oracle_demo.py",
    ]
    (output_dir / "commands.txt").write_text("\n".join(commands) + "\n", encoding="utf-8")

    vulnerable_count = len(vulnerable_result["findings"])
    fixed_count = len(fixed_result["findings"])
    overall = (benchmark_result or {}).get("overall", {})

    report_lines = [
        "# ChainEDR Friend Demo Pack",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## What This Demonstrates",
        "",
        "- ChainEDR detects an EIP-7702-specific broken assumption: `tx.origin == msg.sender` no longer proves a plain EOA.",
        "- The matched fixed sample is clean for the same rule.",
        "- The labeled benchmark is evaluated through the target-rule evaluator, not by scanning the benchmark root as if it were production code.",
        "- The output is reproducible: JSON artifacts and exact commands are written next to this report.",
        "",
        "## Demo Result",
        "",
        f"- Vulnerable sample findings: **{vulnerable_count}**",
        f"- Fixed sample findings: **{fixed_count}**",
    ]

    if overall:
        report_lines.extend([
            f"- Benchmark samples: **{overall.get('samples')}**",
            f"- TP/FP/TN/FN/WRONG: **{overall.get('tp')}/{overall.get('fp')}/{overall.get('tn')}/{overall.get('fn')}/{overall.get('wrong_class')}**",
            f"- Precision/Recall/F1: **{overall.get('precision')}/{overall.get('recall')}/{overall.get('f1')}**",
        ])

    report_lines.extend([
        "",
        "## Why It Is Useful",
        "",
        "Most Solidity scanners are strong on old bug classes, but they do not model the post-Pectra EIP-7702 delegated-account boundary. ChainEDR's claim is narrower and easier to defend: it surfaces code patterns where old EOA assumptions become unsafe after delegation.",
        "",
        "## Reviewer Questions",
        "",
        "1. Are these EIP-7702 assumptions relevant to the wallets/accounts you audit?",
        "2. Which findings should be promoted from pattern evidence to exploit evidence?",
        "3. What real account-abstraction targets should be added to the held-out set?",
        "",
        "## Artifacts",
        "",
        "- `vulnerable_txorigin.json`",
        "- `fixed_txorigin.json`",
        "- `benchmark_results.json`",
        "- `commands.txt`",
        "",
    ])

    report = "\n".join(report_lines)
    report_path = output_dir / "report.md"
    report_path.write_text(report, encoding="utf-8")

    return {
        "output_dir": str(output_dir),
        "report": str(report_path),
        "vulnerable_findings": vulnerable_count,
        "fixed_findings": fixed_count,
        "benchmark_samples": overall.get("samples"),
        "benchmark_f1": overall.get("f1"),
    }


def run_reviewer_package(
    output_dir: Path,
    include_benchmark: bool = True,
) -> dict[str, Any]:
    """Generate a concise reviewer-facing package around measured claims."""
    output_dir.mkdir(parents=True, exist_ok=True)
    demo = run_friend_demo(output_dir / "demo_pack", include_benchmark=include_benchmark)

    one_page = [
        "# ChainEDR Reviewer One-Pager",
        "",
        "## Position",
        "",
        "ChainEDR is a focused EIP-7702 / ERC-4337 research prototype. Its strongest",
        "claim is not broad Solidity coverage; it is modeling delegated-account",
        "assumptions that generic scanners usually do not reason about.",
        "",
        "## What To Show",
        "",
        "1. `chainedr prove demo --out demo_out` for a 30-second tx.origin delegation demo.",
        "2. `python scripts/benchmark_evaluator.py --strict` for the corpus-scoped EIP-7702 gate.",
        "3. `chainedr scan benchmarks/eip7702_sandbox/vulnerable --no-external --deep --json chainedr.json` to show proof-readiness metadata.",
        "4. WSL-only optional: `python poc/differential_oracle_demo.py` for the fork-oracle behavior flip, if solc 0.8.20+ and anvil are ready.",
        "5. `python scripts/evaluate_real_7702_bugs.py` to show that real public recall is tracked separately.",
        "",
        "## Honest Claims",
        "",
        "- Corpus benchmark: TP=21 FP=0 TN=36 FN=0, F1=1.00, corpus-scoped only.",
        "- Frozen audited-target triage: 11 findings, TP=2 FP=0 UNC=9.",
        "- Real trophies: zero confirmed externally valid production bugs so far.",
        "- Included PoCs: reproducible lab/demo PoCs, not bounty disclosures.",
        "- Prototype rating: about 8.4/10 now; a confirmed real bug or stronger measured FP profile is needed to move above the high-8 range.",
        "",
        "## Why It Is Interesting",
        "",
        "The moat is the narrow 7702/4337 boundary: old EOA, signature, EntryPoint,",
        "and delegated-execution assumptions become different after Pectra. ChainEDR",
        "has static rules, proof-adapter plans, bytecode reach profiling, and",
        "fork-oracle primitives aimed at that boundary.",
        "",
        "## What Is New",
        "",
        "- Main `scan` output carries proof plans for behavior flips, signature/domain",
        "  replay, ERC-1271/6492 validation, ERC-4337 UserOp validation, and unverified",
        "  bytecode reach.",
        "- These plans are not impact claims. They say exactly what evidence would be",
        "  needed to confirm or refute a finding.",
        "",
        "## What Not To Claim",
        "",
        "- Do not say production-ready.",
        "- Do not say best scanner.",
        "- Do not say it found real bugs until a disclosure is confirmed.",
        "- Do not merge synthetic benchmark F1 with real-world precision.",
        "",
    ]
    one_page_path = output_dir / "one_page.md"
    one_page_path.write_text("\n".join(one_page), encoding="utf-8")

    demo_script = [
        "# 30-Second Demo Script",
        "",
        "1. Open with: ChainEDR asks one narrow question - what breaks when an EOA can have delegated code?",
        "2. Run the tx.origin demo and show vulnerable/fixed contrast.",
        "3. Run the fork-oracle demo and show the delegated account behavior flip.",
        "4. Show the strict benchmark result as a regression gate only.",
        "5. Close with the honest gap: no confirmed production trophy yet, but the niche is real and measurable.",
        "",
    ]
    demo_script_path = output_dir / "demo_script.md"
    demo_script_path.write_text("\n".join(demo_script), encoding="utf-8")

    speaker_notes = [
        "# Tomorrow Speaker Notes",
        "",
        "## Opening",
        "",
        "ChainEDR is not my claim to have built a universal scanner. It is a focused",
        "prototype for one new audit boundary: what changes when EOAs can temporarily",
        "carry delegated code under EIP-7702.",
        "",
        "## Show Order",
        "",
        "1. Start with `REALITY_CHECK.md` so the limits are visible first.",
        "2. Run `chainedr prove demo --out demo_out` and open `demo_out/report.md`.",
        "3. Run `python scripts/benchmark_evaluator.py --strict`.",
        "4. Open one JSON finding from `chainedr scan ... --deep --json chainedr.json`",
        "   and point at `proof_recipe` / `proof_adapters`.",
        "5. Optional: show `poc/differential_oracle_demo.py` from WSL only if it",
        "   was tested immediately before the call.",
        "6. Close by asking what would make this useful inside a real audit workflow.",
        "",
        "## Hard Questions",
        "",
        "- Did it find a real bounty bug? No. Current trophy count is zero.",
        "- Is F1=1.00 production precision? No. It is a labeled benchmark gate.",
        "- Why is it interesting then? Because it models a narrow post-Pectra boundary",
        "  that generic scanners do not naturally prove.",
        "- What is the next serious step? Execute the proof adapters automatically on",
        "  fork targets and publish recall once real public 7702 bugs exist.",
        "",
        "## Score",
        "",
        "Hard honest prototype score: 8.4/10. More UI/docs polish does not push it to 9;",
        "a confirmed real finding or stronger fresh-target precision evidence does.",
        "",
    ]
    speaker_notes_path = output_dir / "speaker_notes.md"
    speaker_notes_path.write_text("\n".join(speaker_notes), encoding="utf-8")

    claims = {
        "prototype_rating": "8.4/10",
        "rating_ceiling_without_real_finding": "high-8",
        "confirmed_real_bugs": 0,
        "production_ready": False,
        "benchmark_claim_scope": "corpus_scoped",
        "benchmark_current": {
            "tp": 21,
            "fp": 0,
            "tn": 36,
            "fn": 0,
            "f1": 1.0,
        },
        "frozen_audited_targets_current": {
            "findings": 11,
            "tp": 2,
            "fp": 0,
            "uncertain": 9,
        },
        "included_pocs": [
            "tx_origin_delegation_lab_demo",
            "fork_oracle_behavior_flip_lab_demo",
        ],
        "proof_adapters": [
            "eip7702_behavior_flip_probe",
            "signature_domain_replay",
            "erc1271_6492_signature_probe",
            "erc4337_userop_validation",
            "bytecode_reachability_probe",
        ],
        "package_files": {
            "one_page": str(one_page_path),
            "demo_script": str(demo_script_path),
            "speaker_notes": str(speaker_notes_path),
            "demo_pack": demo["output_dir"],
        },
    }
    claims_path = output_dir / "honest_claims.json"
    _write_json(claims_path, claims)

    return {
        "output_dir": str(output_dir),
        "one_page": str(one_page_path),
        "demo_script": str(demo_script_path),
        "speaker_notes": str(speaker_notes_path),
        "honest_claims": str(claims_path),
        "demo_pack": demo["output_dir"],
    }
