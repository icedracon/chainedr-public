"""Evaluate ChainEDR recall on confirmed public EIP-7702 bugs.

This evaluator is deliberately honest about empty data. The synthetic benchmark
can stay perfect while real-world recall remains unknown; this script keeps
those claims separate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eip7702_detector import EIP7702Detector  # noqa: E402
from eip7702_validation import EIP7702ValidationDetector  # noqa: E402


DEFAULT_MANIFEST = ROOT / "benchmarks" / "real_7702_bugs" / "manifest.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _rule_id(finding: Any) -> str:
    return str(getattr(finding, "check_id", "") or getattr(finding, "rule_id", ""))


def _scan_source(path: Path) -> set[str]:
    source = path.read_text(encoding="utf-8", errors="replace")
    rule_ids = {_rule_id(f) for f in EIP7702Detector().check(source)}

    ctx = SimpleNamespace(root=path.parent)
    for finding in EIP7702ValidationDetector()._analyze(source, path, ctx):
        rule_ids.add(_rule_id(finding))

    return {rid for rid in rule_ids if rid}


def evaluate_manifest(manifest_path: Path = DEFAULT_MANIFEST, repo_root: Path = ROOT) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    cases = manifest.get("cases") or []
    if not isinstance(cases, list):
        raise ValueError("manifest cases must be a list")

    if not cases:
        return {
            "benchmark": manifest.get("name", "real_7702_bugs"),
            "manifest": str(manifest_path),
            "status": "empty_manifest",
            "samples": 0,
            "tp": 0,
            "fn": 0,
            "missing": 0,
            "recall": None,
            "results": [],
            "note": "No confirmed public EIP-7702 bug cases are recorded yet.",
        }

    results: list[dict[str, Any]] = []
    tp = 0
    fn = 0
    missing = 0

    for case in cases:
        case_id = str(case.get("id") or f"case_{len(results) + 1}")
        expected = set(case.get("expected_rules") or case.get("rules") or [])
        rel_source = case.get("source") or case.get("path")
        if not rel_source:
            missing += 1
            results.append({
                "id": case_id,
                "status": "missing_source",
                "expected_rules": sorted(expected),
                "matched_rules": [],
                "missed_rules": sorted(expected),
            })
            fn += len(expected)
            continue

        source_path = Path(rel_source)
        if not source_path.is_absolute():
            source_path = repo_root / source_path
        if not source_path.exists():
            missing += 1
            results.append({
                "id": case_id,
                "status": "missing_source",
                "source": str(source_path),
                "expected_rules": sorted(expected),
                "matched_rules": [],
                "missed_rules": sorted(expected),
            })
            fn += len(expected)
            continue

        observed = _scan_source(source_path)
        matched = expected & observed
        missed = expected - observed
        tp += len(matched)
        fn += len(missed)
        results.append({
            "id": case_id,
            "status": "evaluated",
            "source": str(source_path),
            "expected_rules": sorted(expected),
            "observed_rules": sorted(observed),
            "matched_rules": sorted(matched),
            "missed_rules": sorted(missed),
            "public_reference": case.get("public_reference", ""),
        })

    denom = tp + fn
    return {
        "benchmark": manifest.get("name", "real_7702_bugs"),
        "manifest": str(manifest_path),
        "status": "ok",
        "samples": len(cases),
        "tp": tp,
        "fn": fn,
        "missing": missing,
        "recall": round(tp / denom, 4) if denom else None,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    result = evaluate_manifest(args.manifest)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
