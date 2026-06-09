"""Foundry PoC skeletons for ChainEDR Analyzer findings.

These are intentionally proof skeletons, not exploit claims. They give a
researcher a concrete Foundry file with the target path, pre-Pectra assumption,
post-Pectra behavior to prove, and a refutation path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List

try:
    from .reviewer_confidence import reviewer_confidence_for_finding
except ImportError:
    from reviewer_confidence import reviewer_confidence_for_finding


SUPPORTED_RULES = frozenset({
    "AA7702-001",
    "AA7702-002",
    "AA7702-006",
    "AA7702-007",
    "AA7702-008",
    "AA7702-009",
    "AA7702-010",
    "AA7702-011",
    "AA7702-012",
    "AA7702-013",
    "AA7702-016",
    "AA7702-021",
})


def generate_from_scan_json(
    scan_json: Path,
    output_dir: Path,
    include_uncertain: bool = False,
) -> dict:
    data = json.loads(scan_json.read_text(encoding="utf-8"))
    findings = data if isinstance(data, list) else data.get("findings", [])
    return generate_skeletons(findings, output_dir, include_uncertain=include_uncertain)


def generate_skeletons(
    findings: Iterable[dict],
    output_dir: Path,
    include_uncertain: bool = False,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    pocs: List[dict] = []
    for idx, finding in enumerate(findings, 1):
        if not _should_generate(finding, include_uncertain):
            continue
        rule_id = _rule_id(finding)
        target = _target_from_finding(finding)
        filename = f"{idx:03d}_{_safe(rule_id)}_{_safe(target['contract'])}_{_safe(target['function'])}.t.sol"
        path = output_dir / filename
        source = render_foundry_skeleton(finding)
        path.write_text(source, encoding="utf-8")
        pocs.append({
            "rule_id": rule_id,
            "path": str(path),
            "target_contract": target["contract"],
            "target_function": target["function"],
            "proof_status": _proof_status(finding),
            "reviewer_confidence": reviewer_confidence_for_finding(finding),
        })

    manifest = {
        "generated": len(pocs),
        "pocs": pocs,
        "policy": (
            "Skeletons are proof workspaces. They do not imply a confirmed bug "
            "until assertions are completed and run on an authorized target/fork."
        ),
    }
    (output_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (output_dir / "MANIFEST.md").write_text(_manifest_markdown(manifest), encoding="utf-8")
    return manifest


def render_foundry_skeleton(finding: dict) -> str:
    rule_id = _rule_id(finding)
    target = _target_from_finding(finding)
    recipe = _proof_recipe(finding)
    semantic = _semantic_context(finding)
    objective = recipe.get("objective") or _default_objective(rule_id)
    status = _proof_status(finding)
    readiness = recipe.get("readiness", "static_candidate")
    reviewer_confidence = reviewer_confidence_for_finding(finding)
    adapters = ", ".join(
        adapter.get("adapter_id", "adapter")
        for adapter in (finding.get("metadata", {}).get("proof_adapters") or recipe.get("adapters") or [])
    ) or "manual_review"
    missing = []
    sig_missing = ((semantic.get("signature_model") or {}).get("missing") or [])
    userop_missing = ((semantic.get("userop_model") or {}).get("missing") or [])
    if sig_missing:
        missing.append("signature: " + ", ".join(sig_missing))
    if userop_missing:
        missing.append("userOp: " + ", ".join(userop_missing))
    missing_text = "; ".join(missing) or "none recorded"

    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice ChainEDR Analyzer proof skeleton.
/// Rule: {rule_id}
/// Title: {_comment(finding.get("title", ""))}
/// Severity: {finding.get("severity", "UNKNOWN")}
/// Source: {_comment(finding.get("file_path") or finding.get("file") or "unknown")}
/// Location: {_comment(finding.get("location", "unknown"))}
/// Proof status: {status}
/// Readiness: {readiness}
/// Reviewer confidence: {reviewer_confidence["grade"]} ({reviewer_confidence["score"]}/100, {reviewer_confidence["label"]})
/// Adapter: {adapters}
///
/// Pre-Pectra assumption:
/// - The target path assumes an EOA cannot execute delegated code, callbacks,
///   smart-account validation logic, or delegated storage writes.
///
/// Post-Pectra proof objective:
/// - {objective}
///
/// Missing semantic pieces:
/// - {missing_text}
///
/// Refutation path:
/// - If the post-delegation call reverts for the intended reason, or if state
///   and return values are unchanged under a delegated EOA, mark REFUTED.
contract ChainEDR_{_safe(rule_id)}_{_safe(target["contract"])}_{_safe(target["function"])}_PoC is Test {{
    address internal victimEoa = address(0xA11CE);
    address internal attacker = address(0xB0B);
    address internal delegationImplementation = address(0xD3702);
    address internal target = address(0xC0DE);

    function setUp() public {{
        // TODO: vm.createSelectFork(vm.envString("RPC_URL"), <block>);
        // TODO: deploy or bind target contract at `target`.
        // TODO: deploy or bind delegation implementation.
        vm.label(victimEoa, "victimEoa");
        vm.label(attacker, "attacker");
        vm.label(target, "target");
        vm.label(delegationImplementation, "delegationImplementation");
    }}

    function testPrePectraBaseline() public {{
        // TODO: Call {target["contract"]}.{target["function"]} before delegation.
        // Expected: baseline behavior documents the old assumption.
    }}

    function testPostPectraDelegatedEOAPath() public {{
        // TODO: Install delegated code on victimEoa.
        // In local harnesses this may use vm.etch as a stand-in for SET_CODE_TX_TYPE.
        // The real proof should use the closest available fork/Anvil primitive.
        vm.etch(victimEoa, hex"ef0100000000000000000000000000000000000000");

        vm.startPrank(victimEoa);
        // TODO: Call {target["contract"]}.{target["function"]} with exact calldata.
        vm.stopPrank();

        // TODO: Assert the behavior flip or state/value delta.
        // If no flip occurs, mark this finding REFUTED, not confirmed.
    }}
}}
'''


def _should_generate(finding: dict, include_uncertain: bool) -> bool:
    rule_id = _rule_id(finding)
    if rule_id not in SUPPORTED_RULES:
        return False
    if include_uncertain:
        return True
    severity = str(finding.get("severity", "")).upper()
    status = _proof_status(finding)
    return severity in {"CRITICAL", "HIGH"} or status in {
        "CONFIRMABLE",
        "LIKELY_EXPLOITABLE",
        "STATIC_CANDIDATE",
    }


def _rule_id(finding: dict) -> str:
    return (
        finding.get("rule_id")
        or finding.get("check")
        or finding.get("check_id")
        or "UNKNOWN"
    )


def _proof_recipe(finding: dict) -> dict:
    metadata = finding.get("metadata") or {}
    return dict(metadata.get("proof_recipe") or finding.get("proof_recipe") or {})


def _semantic_context(finding: dict) -> dict:
    metadata = finding.get("metadata") or {}
    return dict(metadata.get("semantic_context") or finding.get("semantic_context") or {})


def _proof_status(finding: dict) -> str:
    recipe = _proof_recipe(finding)
    return (
        recipe.get("proof_status")
        or recipe.get("status")
        or finding.get("proof_status")
        or "STATIC_CANDIDATE"
    )


def _target_from_finding(finding: dict) -> dict:
    location = str(finding.get("location") or "")
    file_path = str(finding.get("file_path") or finding.get("file") or "Target.sol")
    contract = Path(file_path).stem or "Target"
    function = "targetFunction"
    if ":semantic" in location and "." in location:
        head = location.split(":", 1)[0]
        contract, function = head.rsplit(".", 1)
    else:
        match = re.search(r"([A-Za-z_]\w*)\(\)", location)
        if match:
            function = match.group(1)
    return {"contract": contract or "Target", "function": function or "targetFunction"}


def _default_objective(rule_id: str) -> str:
    if rule_id in {"AA7702-001", "AA7702-002"}:
        return "show the pre-Pectra EOA gate accepts a delegated EOA after code delegation"
    if rule_id in {"AA7702-006", "AA7702-007", "AA7702-008", "AA7702-009"}:
        return "show delegated execution creates an unexpected storage, proxy, or initialization effect"
    if rule_id in {"AA7702-011", "AA7702-013", "AA7702-021"}:
        return "show UserOperation validation accepts a missing or mutable binding"
    return "confirm or refute the static finding on a fork or local harness"


def _safe(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", str(value))
    value = re.sub(r"_+", "_", value).strip("_")
    return (value or "Unknown")[:64]


def _comment(value: str) -> str:
    return str(value).replace("\n", " ").replace("*/", "* /")[:180]


def _manifest_markdown(manifest: dict) -> str:
    lines = [
        "# ChainEDR PoC Skeleton Manifest",
        "",
        manifest["policy"],
        "",
        "| Rule | Target | Proof / Confidence | Path |",
        "| --- | --- | --- | --- |",
    ]
    for poc in manifest["pocs"]:
        target = f"{poc['target_contract']}.{poc['target_function']}"
        confidence = poc.get("reviewer_confidence") or {}
        status = f"{poc['proof_status']} / {confidence.get('grade', '?')} {confidence.get('score', '?')}"
        lines.append(f"| {poc['rule_id']} | {target} | {status} | `{poc['path']}` |")
    lines.append("")
    return "\n".join(lines)
