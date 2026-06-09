"""
Dynamic confirmation for ChainEDR scan findings.

The first supported confirmation path is EIP-7702 AA7702-002: code-presence
EOA gates. Static analysis can prove that a source pattern is risky; this
module can additionally run a class-level fork probe showing that an EOA's
code length changes after a 7702 delegation.

The confirmation layer is intentionally opt-in and non-fatal by default.
Normal scans should keep working when RPC, Anvil, solc, or web3 are missing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable, List

try:
    from .detector_plugin import Finding
except ImportError:  # pragma: no cover - standalone test imports
    from detector_plugin import Finding


DEFAULT_CONFIRM_EOA = "0x00000000000000000000000000000000DeAd7702"
DEFAULT_CONFIRM_IMPLEMENTATION = "0xd6CEDDe84be40893d153Be9d467CD6aD37875b28"

SUPPORTED_RULES = frozenset({"AA7702-002"})

_EOA_GATE_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ChainEDREOAGateProbe {
    function isEOA(address account) external view returns (bool) {
        return account.code.length == 0;
    }
}
"""


@dataclass(frozen=True)
class ConfirmationOptions:
    enabled: bool = False
    rpc_url: str | None = None
    eoa: str = DEFAULT_CONFIRM_EOA
    implementation: str = DEFAULT_CONFIRM_IMPLEMENTATION
    fork_block: int | None = None
    strict: bool = False


@dataclass
class ConfirmationSummary:
    eligible: int = 0
    confirmed: int = 0
    refuted: int = 0
    skipped: int = 0
    unsupported: int = 0
    status: str = "disabled"
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "eligible": self.eligible,
            "confirmed": self.confirmed,
            "refuted": self.refuted,
            "skipped": self.skipped,
            "unsupported": self.unsupported,
            "status": self.status,
            "reason": self.reason,
        }


def confirm_findings(
    findings: List[Any],
    opts: ConfirmationOptions,
) -> ConfirmationSummary:
    """Attach dynamic-confirmation metadata to supported findings."""
    summary = ConfirmationSummary(status="disabled")
    if not opts.enabled:
        return summary

    eligible = [f for f in findings if _rule_id(f) in SUPPORTED_RULES]
    summary.eligible = len(eligible)
    summary.unsupported = sum(
        1 for f in findings if str(_rule_id(f)).startswith("AA7702-")
        and _rule_id(f) not in SUPPORTED_RULES
    )

    if not eligible:
        summary.status = "no_eligible_findings"
        return summary

    if not opts.rpc_url:
        return _skip(eligible, summary, "RPC URL required; pass --confirm-rpc-url or set RPC_URL", opts.strict)

    if not shutil.which("solc"):
        return _skip(eligible, summary, "solc is required for the AA7702-002 probe contract", opts.strict)

    try:
        verdict = _run_eip7702_code_presence_probe(opts)
    except Exception as exc:
        return _skip(eligible, summary, str(exc), opts.strict)

    status = "confirmed" if verdict.get("dynamically_confirmed") else "refuted"
    proof_status = "CONFIRMED_IMPACT" if status == "confirmed" else "REFUTED"
    summary.status = status
    summary.confirmed = len(eligible) if status == "confirmed" else 0
    summary.refuted = len(eligible) if status == "refuted" else 0

    metadata = {
        "status": status,
        "proof_status": proof_status,
        "mode": "eip7702_code_presence_probe",
        "evidence_scope": "class_probe",
        "finding_specific": False,
        "rule_id": "AA7702-002",
        "eoa": opts.eoa,
        "implementation": opts.implementation,
        "fork_block": opts.fork_block,
        "verdict": verdict,
        "evidence": {
            "before": verdict.get("value_before_delegation"),
            "after": verdict.get("value_after_delegation"),
            "observed_behavior_flip": (
                verdict.get("value_before_delegation") is True
                and verdict.get("value_after_delegation") is False
            ),
            **(verdict.get("evidence") or {}),
        },
        "note": (
            "This confirms the EIP-7702 code-presence behavior class on a fork. "
            "It does not prove exploitability of every source-level instance."
        ),
    }
    for finding in eligible:
        _attach(finding, metadata)
        _update_proof_recipe(finding, proof_status, status)
        if status == "confirmed":
            _mark_confirmed(finding)

    return summary


def dynamic_confirmation_summary(findings: Iterable[Finding]) -> dict:
    """Build an output summary from per-finding dynamic-confirmation metadata."""
    counts: dict[str, int] = {}
    for finding in findings:
        dc = _metadata(finding).get("dynamic_confirmation")
        if not dc:
            continue
        status = dc.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _skip(
    findings: List[Any],
    summary: ConfirmationSummary,
    reason: str,
    strict: bool,
) -> ConfirmationSummary:
    if strict:
        raise RuntimeError(reason)

    summary.status = "skipped"
    summary.reason = reason
    summary.skipped = len(findings)
    metadata = {
        "status": "skipped",
        "proof_status": "STATIC_CANDIDATE",
        "mode": "eip7702_code_presence_probe",
        "evidence_scope": "class_probe",
        "finding_specific": False,
        "rule_id": "AA7702-002",
        "reason": reason,
    }
    for finding in findings:
        _attach(finding, metadata)
    return summary


def _rule_id(finding: Any) -> str:
    if isinstance(finding, dict):
        return str(finding.get("rule_id") or finding.get("check") or "")
    return str(getattr(finding, "rule_id", "") or "")


def _metadata(finding: Any) -> dict:
    if isinstance(finding, dict):
        return dict(finding.get("metadata") or {})
    return dict(getattr(finding, "metadata", {}) or {})


def _attach(finding: Any, metadata: dict) -> None:
    merged = _metadata(finding)
    merged["dynamic_confirmation"] = dict(metadata)
    if isinstance(finding, dict):
        finding["metadata"] = merged
    else:
        finding.metadata = merged


def _update_proof_recipe(finding: Any, proof_status: str, confirmation_status: str) -> None:
    merged = _metadata(finding)
    recipe = dict(merged.get("proof_recipe") or {})
    if recipe:
        recipe["proof_status"] = proof_status
        recipe["dynamic_confirmation_status"] = confirmation_status
        recipe["status"] = (
            "confirmed_with_dynamic_evidence"
            if proof_status == "CONFIRMED_IMPACT"
            else "refuted_by_dynamic_evidence"
        )
        merged["proof_recipe"] = recipe
        if isinstance(finding, dict):
            finding["metadata"] = merged
        else:
            finding.metadata = merged


def _mark_confirmed(finding: Any) -> None:
    if isinstance(finding, dict):
        finding["exploitable"] = True
        try:
            finding["confidence"] = max(float(finding.get("confidence", 0.0)), 0.98)
        except (TypeError, ValueError):
            finding["confidence"] = 0.98
        return
    finding.exploitable = True
    finding.confidence = max(finding.confidence, 0.98)


def _compile_eoa_gate(solc: str = "solc") -> tuple[list, str]:
    proc = subprocess.run(
        [solc, "--combined-json", "abi,bin", "-"],
        input=_EOA_GATE_SRC.encode(),
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace")[:600]
        raise RuntimeError(f"solc failed while compiling confirmation probe: {err}")

    data = json.loads(proc.stdout.decode())
    contract = next(
        value for key, value in data["contracts"].items()
        if key.endswith(":ChainEDREOAGateProbe")
    )
    abi = contract["abi"]
    return (abi if isinstance(abi, list) else json.loads(abi)), contract["bin"]


def _run_eip7702_code_presence_probe(opts: ConfirmationOptions) -> dict:
    try:
        from .fork_oracle import ForkOracle
    except ImportError:  # pragma: no cover - standalone test imports
        from fork_oracle import ForkOracle

    abi, bytecode = _compile_eoa_gate()
    with ForkOracle(rpc_url=opts.rpc_url, fork_block=opts.fork_block) as oracle:
        gate = oracle.deploy(abi, bytecode)
        verdict = oracle.confirm_eoa_gate(
            gate_call=lambda account: gate.functions.isEOA(
                oracle.w3.to_checksum_address(account)
            ).call(),
            eoa=opts.eoa,
            implementation=opts.implementation,
            finding="AA7702-002",
        )
        data = verdict.to_dict()
        data["probe_contract"] = gate.address
        data["observed_fork_block"] = oracle.block
        return data
