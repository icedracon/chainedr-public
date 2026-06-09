"""Proof-adapter planning for focused 7702/4337 findings.

Static findings should not become "real bugs" just because a detector fired.
This module attaches concrete proof plans to findings so the main scan output
answers the auditor question: what evidence would confirm or refute this?
"""
from __future__ import annotations

from typing import Any, Iterable


SIGNATURE_RULES = frozenset({"AA7702-004", "AA7702-010", "AA7702-012", "AA7702-016"})
USEROP_RULE_PREFIXES = ("AA7562-",)
USEROP_RULES = frozenset({"AA7702-011", "AA7702-013", "AA7702-021"})
BYTECODE_RULES = frozenset({"AA7702-006", "AA7702-007", "AA7702-008", "AA7702-014", "AA7702-018"})
BEHAVIOR_FLIP_RULES = frozenset({"AA7702-001", "AA7702-002"})


def attach_proof_adapters(findings: Iterable[Any]) -> None:
    """Mutate normalized Finding objects or legacy dict findings in-place."""
    for finding in findings:
        adapters = build_proof_adapters(finding)
        if not adapters:
            continue
        if isinstance(finding, dict):
            finding["proof_adapters"] = adapters
            recipe = dict(finding.get("proof_recipe") or {})
            if recipe:
                recipe["adapters"] = adapters
                finding["proof_recipe"] = recipe
            continue
        metadata = _metadata(finding)
        metadata["proof_adapters"] = adapters
        recipe = dict(metadata.get("proof_recipe") or {})
        if recipe:
            recipe["adapters"] = adapters
            metadata["proof_recipe"] = recipe
        finding.metadata = metadata


def build_proof_adapters(finding: Any) -> list[dict]:
    rule_id = _rule_id(finding)
    metadata = _metadata(finding)
    semantic = _semantic_context(finding, metadata)
    proof_recipe = _proof_recipe(finding, metadata)

    adapters: list[dict] = []
    if rule_id in BEHAVIOR_FLIP_RULES:
        adapters.append(_behavior_flip_adapter(rule_id, proof_recipe))
    if _needs_signature_adapter(rule_id, semantic):
        adapters.append(_signature_replay_adapter(rule_id, semantic, proof_recipe))
    if _needs_erc1271_adapter(rule_id, semantic):
        adapters.append(_erc1271_6492_adapter(rule_id, semantic, proof_recipe))
    if _needs_userop_adapter(rule_id, semantic):
        adapters.append(_userop_adapter(rule_id, semantic, proof_recipe))
    if _needs_bytecode_adapter(rule_id, metadata, proof_recipe):
        adapters.append(_bytecode_adapter(rule_id, metadata, proof_recipe))
    return adapters


def _behavior_flip_adapter(rule_id: str, proof_recipe: dict) -> dict:
    return {
        "adapter_id": "eip7702_behavior_flip_probe",
        "family": "delegated_eoa_behavior_flip",
        "rule_id": rule_id,
        "status": "SUPPORTED_BY_SCAN_CONFIRM" if rule_id == "AA7702-002" else "READY_TO_BUILD_HARNESS",
        "proof_status": "CONFIRMABLE" if rule_id == "AA7702-002" else "STATIC_CANDIDATE",
        "requires": ["rpc_url", "victim_eoa", "implementation", "target_call"],
        "evidence_plan": [
            "call the target gate before delegation",
            "install EIP-7702 delegation code on the EOA in a fork",
            "call the same target gate after delegation",
            "record before/after return values and EOA code bytes",
        ],
        "source_kind": proof_recipe.get("kind", "fork_oracle_behavior_flip"),
    }


def build_bytecode_proof_adapters(profile: Any) -> list[dict]:
    """Attach plans to an unverified-bytecode profile without claiming impact."""
    if hasattr(profile, "to_dict"):
        data = profile.to_dict()
    else:
        data = dict(profile or {})
    flags = set(data.get("risk_flags") or [])
    guard = data.get("guard_surface") or {}
    known = data.get("known_selectors") or {}
    recommended = list(data.get("recommended_probes") or [])
    surfaces = list(data.get("proof_surfaces") or [])

    adapters: list[dict] = []
    if {"erc20_balance_sweep_surface", "token_allowance_surface"} & flags:
        adapters.append({
            "adapter_id": "bytecode_asset_sweep_probe",
            "family": "unverified_bytecode_asset_flow",
            "status": "READY_TO_RUN_WITH_FORK_INPUTS",
            "requires": ["rpc_url", "implementation_bytecode", "funded_test_token_or_nft", "victim_eoa", "attacker"],
            "candidate_selectors": sorted(known),
            "recommended_probes": recommended,
            "proof_surfaces": surfaces,
            "evidence_plan": [
                "install runtime bytecode on a fork test address",
                "fund delegated victim with ERC-20/NFT asset",
                "invoke candidate execute/sweep/approval calldata",
                "compare victim/attacker balances and allowances",
            ],
        })
    if guard.get("hints"):
        adapters.append({
            "adapter_id": "bytecode_guard_surface_review",
            "family": "unverified_bytecode_guard_classification",
            "status": "STATIC_REACHABILITY_ONLY",
            "guard_strength": guard.get("guard_strength", "none"),
            "hints": guard.get("hints", []),
            "recommended_probes": recommended,
            "proof_surfaces": surfaces,
            "evidence_plan": [
                "map selectors to auth/domain/nonce/UserOp surfaces",
                "prioritize weak or missing guard surfaces for fork probing",
                "do not treat guard hints as proof of safety",
            ],
        })
    return adapters


def _needs_signature_adapter(rule_id: str, semantic: dict) -> bool:
    model = semantic.get("signature_model") or {}
    return bool(rule_id in SIGNATURE_RULES or model.get("missing"))


def _needs_erc1271_adapter(rule_id: str, semantic: dict) -> bool:
    model = semantic.get("signature_model") or {}
    return bool(
        rule_id == "AA7702-016"
        or "erc1271_fallback" in (model.get("missing") or [])
        or (model.get("verifies_signature") and not model.get("uses_erc1271"))
    )


def _needs_userop_adapter(rule_id: str, semantic: dict) -> bool:
    model = semantic.get("userop_model") or {}
    return bool(
        rule_id.startswith(USEROP_RULE_PREFIXES)
        or rule_id in USEROP_RULES
        or model.get("missing")
    )


def _needs_bytecode_adapter(rule_id: str, metadata: dict, proof_recipe: dict) -> bool:
    return bool(
        rule_id in BYTECODE_RULES
        or metadata.get("bytecode_profile")
        or str(proof_recipe.get("kind", "")).startswith(("delegated_", "token_", "value_"))
    )


def _signature_replay_adapter(rule_id: str, semantic: dict, proof_recipe: dict) -> dict:
    model = semantic.get("signature_model") or {}
    missing = list(model.get("missing") or [])
    mutations = []
    if "chain_id" in missing:
        mutations.append("replay_same_signature_with_different_chain_id")
    if "verifying_contract" in missing:
        mutations.append("replay_same_signature_against_second_verifying_contract")
    if "nonce" in missing:
        mutations.append("replay_same_signature_twice_or_after_nonce_drift")
    if not mutations:
        mutations.append("negative_control_signature_replay_attempt")
    return {
        "adapter_id": "signature_domain_replay",
        "family": "signature_domain_replay",
        "rule_id": rule_id,
        "status": "READY_TO_BUILD_HARNESS",
        "proof_status": "STATIC_CANDIDATE",
        "missing_bindings": missing,
        "mutations": mutations,
        "requires": ["target_function_abi", "valid_signature_fixture", "signer_key_or_test_vector"],
        "evidence_plan": [
            "build a valid baseline signature accepted by the target path",
            "mutate only the missing domain/nonce binding",
            "prove replay is accepted or record refutation",
            "emit calldata, digest, signer, recovered address, and state diff",
        ],
        "source_kind": proof_recipe.get("kind", "signature_context_review"),
    }


def _erc1271_6492_adapter(rule_id: str, semantic: dict, proof_recipe: dict) -> dict:
    model = semantic.get("signature_model") or {}
    return {
        "adapter_id": "erc1271_6492_signature_probe",
        "family": "smart_account_signature_validation",
        "rule_id": rule_id,
        "status": "READY_TO_BUILD_HARNESS",
        "proof_status": "STATIC_CANDIDATE",
        "uses_erc1271": bool(model.get("uses_erc1271")),
        "uses_erc6492": bool(model.get("uses_erc6492")),
        "requires": ["target_signature_entrypoint", "smart_account_signer_fixture", "erc1271_magic_value_check"],
        "evidence_plan": [
            "compare EOA ECDSA signature acceptance with ERC-1271 smart-account signature acceptance",
            "if undeployed-account support is present, wrap or unwrap ERC-6492 signature envelope",
            "record expected magic value, actual return/revert, and delegated EOA code state",
        ],
        "source_kind": proof_recipe.get("kind", "signature_context_review"),
    }


def _userop_adapter(rule_id: str, semantic: dict, proof_recipe: dict) -> dict:
    model = semantic.get("userop_model") or {}
    missing = list(model.get("missing") or [])
    mutations = []
    if "userOpHash" in missing:
        mutations.append("swap_userOpHash_or_callData_without_resigning")
    if "nonce" in missing:
        mutations.append("reuse_or_skip_userOp_nonce")
    if "entryPoint" in missing:
        mutations.append("call_validateUserOp_from_non_entrypoint")
    if "signature_verification" in missing:
        mutations.append("submit_userOp_with_empty_or_random_signature")
    if not mutations:
        mutations.append("negative_control_userop_mutation")
    return {
        "adapter_id": "erc4337_userop_validation",
        "family": "userop_validation_simulation",
        "rule_id": rule_id,
        "status": "READY_TO_BUILD_HARNESS",
        "proof_status": "STATIC_CANDIDATE",
        "missing_bindings": missing,
        "mutations": mutations,
        "requires": ["entrypoint_address", "account_address", "packed_userop_builder", "baseline_valid_userop"],
        "evidence_plan": [
            "build one baseline UserOperation that validates",
            "mutate exactly one missing binding",
            "run simulateValidation or direct validateUserOp negative control",
            "emit validationData, revert data, calldata, nonce, and userOpHash",
        ],
        "source_kind": proof_recipe.get("kind", "userop_validation_review"),
    }


def _bytecode_adapter(rule_id: str, metadata: dict, proof_recipe: dict) -> dict:
    profile = metadata.get("bytecode_profile") or {}
    return {
        "adapter_id": "bytecode_reachability_probe",
        "family": "unverified_bytecode_reach",
        "rule_id": rule_id,
        "status": "READY_WITH_RUNTIME_BYTECODE",
        "proof_status": "STATIC_CANDIDATE",
        "risk_flags": profile.get("risk_flags", []),
        "guard_surface": profile.get("guard_surface", {}),
        "requires": ["runtime_bytecode_or_address", "rpc_url", "victim_eoa", "attacker", "candidate_calldata"],
        "evidence_plan": [
            "fetch or install runtime bytecode",
            "classify selectors and guard surface",
            "run state-write/value-flow/token/NFT probes where inputs are available",
            "only alert if live impact and calldata/evidence are present",
        ],
        "source_kind": proof_recipe.get("kind", "bytecode_oracle_candidate"),
    }


def _rule_id(finding: Any) -> str:
    if isinstance(finding, dict):
        return str(finding.get("rule_id") or finding.get("check") or finding.get("check_id") or "")
    return str(getattr(finding, "rule_id", "") or getattr(finding, "check_id", "") or "")


def _metadata(finding: Any) -> dict:
    if isinstance(finding, dict):
        return dict(finding.get("metadata") or {})
    metadata = dict(getattr(finding, "metadata", {}) or {})
    if hasattr(finding, "semantic_context"):
        metadata.setdefault("semantic_context", getattr(finding, "semantic_context", {}) or {})
    if hasattr(finding, "proof_metadata"):
        metadata.setdefault("proof_recipe", finding.proof_metadata())
    return metadata


def _proof_recipe(finding: Any, metadata: dict) -> dict:
    if isinstance(finding, dict):
        return dict(finding.get("proof_recipe") or metadata.get("proof_recipe") or {})
    return dict(metadata.get("proof_recipe") or {})


def _semantic_context(finding: Any, metadata: dict) -> dict:
    if isinstance(finding, dict):
        return dict(
            finding.get("semantic_context")
            or metadata.get("semantic_context")
            or (_proof_recipe(finding, metadata).get("semantic") if _proof_recipe(finding, metadata) else {})
            or {}
        )
    recipe = _proof_recipe(finding, metadata)
    return dict(metadata.get("semantic_context") or recipe.get("semantic") or {})
