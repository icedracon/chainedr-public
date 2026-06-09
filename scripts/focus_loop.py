"""Focused ChainEDR loop: harvest manifest -> prove evidence -> alert.

The loop is conservative by design. Static findings are candidates. Alerts are
emitted only when a proof entry is marked confirmed, live-impact, and includes a
PoC handle such as calldata, a PoC path, or evidence bundle path.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eip7702_detector import EIP7702Detector  # noqa: E402
from proof_adapters import attach_proof_adapters  # noqa: E402


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _scan_static_source_tree(path: Path) -> list[dict[str, Any]]:
    detector = EIP7702Detector()
    findings: list[dict[str, Any]] = []
    if path.is_file() and path.suffix == ".sol":
        files = [path]
        root = path.parent
    else:
        files = sorted(path.rglob("*.sol"))
        root = path

    sources = {
        str(sol_file.relative_to(root)): sol_file.read_text(encoding="utf-8", errors="replace")
        for sol_file in files
    }
    scanned, _ctx = detector.scan_files(sources, deep=True)
    for rel, finding in scanned:
        proof_recipe = finding.proof_metadata()
        findings.append({
            "rule_id": finding.check_id,
            "severity": finding.severity,
            "title": finding.title,
            "file": rel,
            "location": finding.location,
            "confidence": round(finding.confidence, 2),
            "status": "candidate_needs_dynamic_proof",
            "semantic_context": finding.semantic_context,
            "proof_recipe": proof_recipe,
            "proof_status": proof_recipe.get("proof_status"),
        })
    attach_proof_adapters(findings)
    return findings


def _has_poc_handle(proof: dict[str, Any]) -> bool:
    return bool(
        proof.get("poc")
        or proof.get("poc_path")
        or proof.get("calldata")
        or proof.get("evidence")
        or proof.get("evidence_bundle")
    )


def _alert_from_proof(target: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any] | None:
    confirmed = proof.get("confirmed") is True
    live_impact = proof.get("live_impact") is True or proof.get("impact_confirmed") is True
    has_poc = _has_poc_handle(proof)
    if not (confirmed and live_impact and has_poc):
        return None

    return {
        "target": target.get("name") or target.get("address") or target.get("path") or "unknown",
        "address": target.get("address", ""),
        "chain_id": target.get("chain_id", ""),
        "rule_id": proof.get("rule_id", ""),
        "impact": proof.get("impact", "confirmed_live_impact"),
        "reason": "confirmed_with_live_impact_and_poc",
        "poc": proof.get("poc") or proof.get("poc_path") or "",
        "calldata": proof.get("calldata", ""),
        "evidence": proof.get("evidence") or proof.get("evidence_bundle") or "",
    }


def run_focus_loop(manifest_path: Path, repo_root: Path = ROOT) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    targets = manifest.get("targets") or []
    if not isinstance(targets, list):
        raise ValueError("manifest targets must be a list")

    results: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []

    for target in targets:
        rel_path = target.get("path") or target.get("source")
        static_findings: list[dict[str, Any]] = []
        scan_status = "no_source_path"
        if rel_path:
            source_path = Path(rel_path)
            if not source_path.is_absolute():
                source_path = repo_root / source_path
            if source_path.exists():
                static_findings = _scan_static_source_tree(source_path)
                scan_status = "scanned"
            else:
                scan_status = "missing_source_path"

        target_alerts: list[dict[str, Any]] = []
        rejected_proofs: list[dict[str, Any]] = []
        for proof in target.get("proofs") or []:
            alert = _alert_from_proof(target, proof)
            if alert is None:
                rejected_proofs.append({
                    "rule_id": proof.get("rule_id", ""),
                    "confirmed": proof.get("confirmed") is True,
                    "live_impact": proof.get("live_impact") is True or proof.get("impact_confirmed") is True,
                    "has_poc": _has_poc_handle(proof),
                    "status": "not_alertable",
                })
                continue
            target_alerts.append(alert)
            alerts.append(alert)

        results.append({
            "target": target.get("name") or target.get("address") or rel_path or "unknown",
            "scan_status": scan_status,
            "static_candidates": len(static_findings),
            "proofs": len(target.get("proofs") or []),
            "alerts": len(target_alerts),
            "findings": static_findings,
            "target_alerts": target_alerts,
            "rejected_proofs": rejected_proofs,
        })

    return {
        "manifest": str(manifest_path),
        "alert_policy": "static findings are candidates; only confirmed + live_impact + PoC/calldata/evidence emits alert",
        "summary": {
            "targets": len(targets),
            "static_candidates": sum(r["static_candidates"] for r in results),
            "proofs": sum(r["proofs"] for r in results),
            "alerts": len(alerts),
        },
        "alerts": alerts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, required=True, help="JSON manifest with a targets list")
    parser.add_argument("--out", type=Path, help="Where to write the JSON loop report")
    args = parser.parse_args()

    result = run_focus_loop(args.targets)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
