"""
EIP-7702 sandbox policy and pre-behavior trace model.

This module turns detector hits into structured evidence for the research
claim: ChainEDR performs pre-execution behavioral analysis of delegated EOA
workflows against explicit sandbox boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SandboxPolicy:
    """Policy boundaries an EIP-7702 delegated account should not bypass."""

    identity_boundary: str = (
        "EOA identity must not be treated as proof of non-programmable behavior."
    )
    code_boundary: str = (
        "Code-presence checks must not be the only boundary between EOAs and contracts."
    )
    storage_boundary: str = (
        "Delegated code must not assume isolated or contract-owned storage layout."
    )
    call_boundary: str = (
        "Calls, callbacks, hooks, and delegatecalls must preserve expected trust boundaries."
    )
    validation_boundary: str = (
        "Authorization, signature, nonce, and EntryPoint validation must bind to delegated account semantics."
    )
    replay_boundary: str = (
        "Delegation authorizations must be bound to chain, nonce, ordering, and domain context."
    )
    revocation_boundary: str = (
        "Delegation must have an auditable revocation and liveness path."
    )
    gas_boundary: str = (
        "Sponsored or delegated execution must bound gas use and griefing impact."
    )

    def to_dict(self) -> dict[str, str]:
        return {
            "identity_boundary": self.identity_boundary,
            "code_boundary": self.code_boundary,
            "storage_boundary": self.storage_boundary,
            "call_boundary": self.call_boundary,
            "validation_boundary": self.validation_boundary,
            "replay_boundary": self.replay_boundary,
            "revocation_boundary": self.revocation_boundary,
            "gas_boundary": self.gas_boundary,
        }

    def rule_for(self, boundary: str) -> str:
        return self.to_dict().get(boundary, "")


@dataclass(frozen=True)
class PreBehaviorTrace:
    """Pre-execution trace inferred from source-level EIP-7702 assumptions."""

    assumptions_detected: tuple[str, ...] = ()
    delegated_behavior_possible: tuple[str, ...] = ()
    violated_sandbox_rule: str = ""
    violated_boundary: str = ""
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    bypass_class: str = ""
    policy: SandboxPolicy = field(default_factory=SandboxPolicy)

    def to_dict(self) -> dict:
        return {
            "assumptions_detected": list(self.assumptions_detected),
            "delegated_behavior_possible": list(self.delegated_behavior_possible),
            "violated_sandbox_rule": self.violated_sandbox_rule,
            "violated_boundary": self.violated_boundary,
            "evidence": list(self.evidence),
            "confidence": round(self.confidence, 2),
            "bypass_class": self.bypass_class,
            "policy": self.policy.to_dict(),
        }


@dataclass(frozen=True)
class _TraceTemplate:
    boundary: str
    bypass_class: str
    assumptions: tuple[str, ...]
    delegated_behaviors: tuple[str, ...]


DEFAULT_SANDBOX_POLICY = SandboxPolicy()


RULE_TRACE_TEMPLATES: dict[str, _TraceTemplate] = {
    "AA7702-001": _TraceTemplate(
        boundary="identity_boundary",
        bypass_class="identity_assumption_bypass",
        assumptions=("tx.origin == msg.sender means the caller is a plain EOA",),
        delegated_behaviors=(
            "A delegated EOA can execute account code while retaining EOA caller identity",
        ),
    ),
    "AA7702-002": _TraceTemplate(
        boundary="code_boundary",
        bypass_class="code_presence_bypass",
        assumptions=("code.length == 0 or isContract() means no executable behavior",),
        delegated_behaviors=(
            "An EOA can be authorized to execute delegated code even when old code checks pass",
        ),
    ),
    "AA7702-003": _TraceTemplate(
        boundary="call_boundary",
        bypass_class="callback_reentrancy_bypass",
        assumptions=("EOA callbacks cannot run attacker-controlled code",),
        delegated_behaviors=("A delegated EOA can reenter during ETH or token callbacks",),
    ),
    "AA7702-004": _TraceTemplate(
        boundary="replay_boundary",
        bypass_class="cross_chain_delegation_replay",
        assumptions=("Delegation authorization is bound to the intended chain",),
        delegated_behaviors=("A chainId=0 or missing chain binding can replay delegated authority",),
    ),
    "AA7702-005": _TraceTemplate(
        boundary="revocation_boundary",
        bypass_class="missing_delegation_revocation",
        assumptions=("Delegated authority can be safely disabled after assignment",),
        delegated_behaviors=("A delegated account can remain active without an explicit revocation path",),
    ),
    "AA7702-006": _TraceTemplate(
        boundary="call_boundary",
        bypass_class="delegatecall_context_escape",
        assumptions=("Delegation target execution stays inside the intended account logic",),
        delegated_behaviors=("delegatecall can swap execution context and mutate delegated EOA storage",),
    ),
    "AA7702-007": _TraceTemplate(
        boundary="storage_boundary",
        bypass_class="delegated_storage_collision",
        assumptions=("Delegation target storage is isolated from EOA/account storage",),
        delegated_behaviors=("Delegated code can read or overwrite storage slots expected by other account logic",),
    ),
    "AA7702-008": _TraceTemplate(
        boundary="storage_boundary",
        bypass_class="initialization_race",
        assumptions=("Delegated account initialization is atomic and cannot be front-run",),
        delegated_behaviors=("A delegated account can execute before owner, nonce, or guard state is initialized",),
    ),
    "AA7702-009": _TraceTemplate(
        boundary="storage_boundary",
        bypass_class="proxy_delegation_conflict",
        assumptions=("Proxy storage layout and delegated account storage cannot conflict",),
        delegated_behaviors=("ERC-1967 proxy slots can collide with delegation target assumptions",),
    ),
    "AA7702-010": _TraceTemplate(
        boundary="validation_boundary",
        bypass_class="permit_validation_bypass",
        assumptions=("permit/ecrecover validates a normal EOA signer model",),
        delegated_behaviors=("Delegated EOAs can change signer semantics without EIP-1271-style validation",),
    ),
    "AA7702-011": _TraceTemplate(
        boundary="replay_boundary",
        bypass_class="batch_authorization_replay",
        assumptions=("Batched delegated operations execute in the validated order exactly once",),
        delegated_behaviors=("Delegated batch authorizations can be reordered or replayed across operations",),
    ),
    "AA7702-012": _TraceTemplate(
        boundary="replay_boundary",
        bypass_class="nonce_gap_exploitation",
        assumptions=("Transaction nonce and delegation authorization nonce advance together",),
        delegated_behaviors=("Separate nonce domains can leave replayable gaps in delegated authorization state",),
    ),
    "AA7702-013": _TraceTemplate(
        boundary="gas_boundary",
        bypass_class="gas_sponsorship_griefing",
        assumptions=("Sponsored delegated execution has bounded gas exposure",),
        delegated_behaviors=("Delegated account code can consume sponsor gas before useful validation or effects",),
    ),
    "AA7702-014": _TraceTemplate(
        boundary="call_boundary",
        bypass_class="value_transfer_behavior_confusion",
        assumptions=("Sending ETH to an EOA has no programmable side effects",),
        delegated_behaviors=("Value transfer to a delegated EOA can trigger code paths and callbacks",),
    ),
    "AA7702-015": _TraceTemplate(
        boundary="code_boundary",
        bypass_class="delegation_target_liveness_loss",
        assumptions=("Delegation target code remains available and safe for account execution",),
        delegated_behaviors=("selfdestruct or destructive target logic can break delegated account liveness",),
    ),
    "AA7702-016": _TraceTemplate(
        boundary="validation_boundary",
        bypass_class="signature_context_bypass",
        assumptions=("ecrecover is enough to validate account ownership for EOA callers",),
        delegated_behaviors=("Delegated accounts can require contract-style signature validation and context binding",),
    ),
    "AA7702-017": _TraceTemplate(
        boundary="call_boundary",
        bypass_class="token_hook_reentrancy_bypass",
        assumptions=("EOA token recipients cannot execute hook code",),
        delegated_behaviors=("Delegated EOAs can receive token hooks and reenter account workflows",),
    ),
    "AA7702-018": _TraceTemplate(
        boundary="call_boundary",
        bypass_class="approval_workflow_bypass",
        assumptions=("Approval state changes cannot be combined with delegated account execution surprises",),
        delegated_behaviors=("Delegated EOA workflows can front-run or reorder approval and transferFrom behavior",),
    ),
    "AA7702-019": _TraceTemplate(
        boundary="revocation_boundary",
        bypass_class="single_relayer_liveness_bypass",
        assumptions=("A single relayer remains trusted and live for delegated execution",),
        delegated_behaviors=("Delegated account availability can be captured by one hardcoded relayer path",),
    ),
    "AA7702-020": _TraceTemplate(
        boundary="storage_boundary",
        bypass_class="missing_storage_namespace",
        assumptions=("Delegation target state slots remain stable across redelegation",),
        delegated_behaviors=("Missing ERC-7201-style namespacing can corrupt state across delegated implementations",),
    ),
    "AA7702-021": _TraceTemplate(
        boundary="validation_boundary",
        bypass_class="entrypoint_version_mismatch",
        assumptions=("A hardcoded EntryPoint version validates all account-abstraction flows",),
        delegated_behaviors=("Delegated accounts can depend on newer EntryPoint validation semantics",),
    ),
}


def _clamp_confidence(confidence: float) -> float:
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, value))


def build_pre_behavior_trace(
    check_id: str,
    *,
    title: str = "",
    location: str = "",
    description: str = "",
    confidence: float = 0.0,
    policy: SandboxPolicy = DEFAULT_SANDBOX_POLICY,
) -> PreBehaviorTrace:
    """Build a sandbox trace for an EIP-7702 rule id."""

    template = RULE_TRACE_TEMPLATES.get(
        check_id,
        _TraceTemplate(
            boundary="validation_boundary",
            bypass_class="unknown_eip7702_sandbox_bypass",
            assumptions=("A pre-7702 account behavior assumption is still valid",),
            delegated_behaviors=("Delegated EOA execution may violate the assumed account boundary",),
        ),
    )

    evidence = tuple(
        item
        for item in (check_id, title, location, description)
        if isinstance(item, str) and item.strip()
    )

    return PreBehaviorTrace(
        assumptions_detected=template.assumptions,
        delegated_behavior_possible=template.delegated_behaviors,
        violated_sandbox_rule=policy.rule_for(template.boundary),
        violated_boundary=template.boundary,
        evidence=evidence,
        confidence=_clamp_confidence(confidence),
        bypass_class=template.bypass_class,
        policy=policy,
    )
