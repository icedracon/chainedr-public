"""Reviewer-facing evidence quality grading for ChainEDR findings.

The score describes proof/evidence maturity, not exploit certainty. A critical
regex finding can still have a low evidence grade until semantic context,
dynamic confirmation, or a concrete PoC path is attached.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


GRADE_THRESHOLDS = (
    (85, "A", "strong_evidence"),
    (70, "B", "review_ready"),
    (55, "C", "triage_candidate"),
    (0, "D", "needs_evidence"),
)


def reviewer_confidence_for_finding(finding: Mapping[str, Any]) -> dict:
    """Return a stable auditor confidence object for a finding dictionary."""
    metadata = _mapping(finding.get("metadata"))
    semantic = _semantic_context(finding, metadata)
    recipe = _proof_recipe(finding, metadata)
    dynamic = _mapping(metadata.get("dynamic_confirmation"))
    adapters = _proof_adapters(finding, metadata, recipe)
    analysis_depth = str(
        finding.get("analysis_depth")
        or metadata.get("analysis_depth")
        or semantic.get("analysis")
        or "static_heuristic"
    )

    score = 25
    evidence: list[str] = []
    gaps: list[str] = []

    if analysis_depth in {"dynamic_confirmation"} or dynamic.get("status") == "confirmed":
        score += 40
        evidence.append("dynamic_confirmation")
    elif analysis_depth in {"standard_json_ast", "deep_ast", "semantic_index"}:
        score += 25
        evidence.append(analysis_depth)
    elif analysis_depth == "deep_fallback":
        score += 18
        evidence.append("deep_fallback")
    elif analysis_depth == "regex":
        score += 10
        evidence.append("regex_signal")
        gaps.append("semantic_or_ast_confirmation")
    elif analysis_depth == "external_tool":
        score += 14
        evidence.append("external_tool_signal")
    else:
        gaps.append("semantic_or_ast_confirmation")

    if semantic.get("semantic_index"):
        score += 10
        evidence.append("project_semantic_index")
    if _has_semantic_ir_flow_facts(semantic):
        score += 8
        evidence.append("semantic_ir_flow_facts")
    if _has_call_graph_edges(semantic):
        score += 6
        evidence.append("ir_call_graph")
    if _has_proxy_or_delegation_context(semantic):
        score += 6
        evidence.append("proxy_or_delegation_context")
    if _has_missing_signature_or_userop_pieces(semantic):
        evidence.append("explicit_missing_proof_pieces")
        gaps.append("complete_signature_or_userop_model")

    proof_status = str(
        recipe.get("proof_status")
        or recipe.get("status")
        or finding.get("proof_status")
        or ""
    )
    if proof_status in {"CONFIRMED_IMPACT", "confirmed"}:
        score += 35
        evidence.append("confirmed_impact")
    elif proof_status in {"CONFIRMABLE", "LIKELY_EXPLOITABLE"}:
        score += 18
        evidence.append("confirmable_proof_path")
    elif proof_status in {"STATIC_CANDIDATE", "needs_dynamic_confirmation"}:
        score += 8
        evidence.append("static_proof_candidate")
        gaps.append("dynamic_confirmation_or_manual_reproduction")

    if adapters:
        score += 8
        evidence.append("proof_adapter_available")
    else:
        gaps.append("proof_adapter")

    auto_poc = str(recipe.get("auto_poc_status") or finding.get("auto_poc_status") or "")
    if auto_poc:
        score += 5
        evidence.append(f"auto_poc:{auto_poc}")
    else:
        gaps.append("poc_skeleton")

    score = max(0, min(100, score))
    grade, label = _grade(score)
    tier, tier_reason = _review_tier(
        grade=grade,
        evidence=evidence,
        gaps=gaps,
        proof_status=proof_status,
    )
    return {
        "score": score,
        "grade": grade,
        "label": label,
        "tier": tier,
        "tier_reason": tier_reason,
        "analysis_depth": analysis_depth,
        "proof_status": proof_status or "unknown",
        "evidence": _dedupe(evidence),
        "gaps": _dedupe(gaps),
    }


def attach_reviewer_confidence(finding: dict) -> dict:
    """Attach reviewer confidence in-place and return the same dictionary."""
    finding["reviewer_confidence"] = reviewer_confidence_for_finding(finding)
    return finding


def findings_with_reviewer_confidence(findings: list[dict]) -> list[dict]:
    """Return copies of findings with reviewer confidence attached."""
    enriched = [deepcopy(finding) for finding in findings]
    for finding in enriched:
        attach_reviewer_confidence(finding)
    return enriched


def _semantic_context(finding: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict:
    return dict(_mapping(metadata.get("semantic_context") or finding.get("semantic_context")))


def _proof_recipe(finding: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict:
    return dict(_mapping(metadata.get("proof_recipe") or finding.get("proof_recipe")))


def _proof_adapters(
    finding: Mapping[str, Any],
    metadata: Mapping[str, Any],
    recipe: Mapping[str, Any],
) -> list:
    adapters = (
        metadata.get("proof_adapters")
        or recipe.get("adapters")
        or finding.get("proof_adapters")
        or []
    )
    return adapters if isinstance(adapters, list) else []


def _has_proxy_or_delegation_context(semantic: Mapping[str, Any]) -> bool:
    index = _mapping(semantic.get("semantic_index"))
    summary = _mapping(index.get("summary"))
    return bool(
        semantic.get("proxy_model")
        or semantic.get("delegation_model")
        or summary.get("proxy_contracts")
        or summary.get("delegation_contracts")
    )


def _has_semantic_ir_flow_facts(semantic: Mapping[str, Any]) -> bool:
    semantic_ir = _mapping(semantic.get("semantic_ir"))
    summary = _mapping(semantic_ir.get("summary"))
    if summary.get("facts"):
        return True
    for function in semantic_ir.get("functions") or []:
        if not isinstance(function, Mapping):
            continue
        for key in (
            "storage_reads",
            "storage_writes",
            "external_calls",
            "delegatecalls",
            "value_transfers",
            "internal_calls",
            "auth_checks",
            "tx_origin_checks",
            "code_size_checks",
            "signature_checks",
            "calldata_parameters",
        ):
            if function.get(key):
                return True
    return False


def _has_call_graph_edges(semantic: Mapping[str, Any]) -> bool:
    call_graph = _mapping(semantic.get("call_graph"))
    summary = _mapping(call_graph.get("summary"))
    if summary.get("edges"):
        return True
    edges = call_graph.get("edges") or []
    return bool(edges)


def _has_missing_signature_or_userop_pieces(semantic: Mapping[str, Any]) -> bool:
    signature_model = _mapping(semantic.get("signature_model"))
    userop_model = _mapping(semantic.get("userop_model"))
    return bool(signature_model.get("missing") or userop_model.get("missing"))


def _grade(score: int) -> tuple[str, str]:
    for threshold, grade, label in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade, label
    return "D", "needs_evidence"


def _review_tier(
    *,
    grade: str,
    evidence: list[str],
    gaps: list[str],
    proof_status: str,
) -> tuple[str, str]:
    if (
        proof_status in {"CONFIRMED_IMPACT", "confirmed"}
        or "confirmed_impact" in evidence
        or "dynamic_confirmation" in evidence
    ):
        return (
            "CONFIRMED",
            "dynamic confirmation or confirmed-impact evidence is attached",
        )
    if grade in {"A", "B"}:
        return (
            "CANDIDATE",
            "review-ready evidence is present, but impact still needs manual or dynamic confirmation",
        )
    if grade == "C":
        return (
            "CANDIDATE",
            "static evidence is triage-ready, but important proof gaps remain",
        )
    if "semantic_or_ast_confirmation" in gaps:
        return (
            "INFORMATIONAL",
            "low-evidence static signal; use as context until semantic confirmation exists",
        )
    return (
        "INFORMATIONAL",
        "low-evidence signal; keep for context unless a reviewer upgrades it",
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out
