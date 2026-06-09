"""Private-beta wording and severity normalization for EIP-7702 findings.

The core detector intentionally stays stable while the semantic rules are being
migrated from pattern matching toward AST/call-graph-backed checks. This module
patches release-critical wording mistakes at finding construction time so JSON,
SARIF, evidence bundles, and terminal output share the same corrected model.

The normalizer is deliberately narrow. It does not hide findings or turn static
candidates into confirmed vulnerabilities.
"""

from __future__ import annotations

from typing import Any

_INSTALLED = False


def _replace(text: str, old: str, new: str) -> str:
    return text.replace(old, new) if old in text else text


def normalize_finding_text(finding: Any) -> Any:
    """Normalize known inaccurate EIP-7702 wording on a finding-like object."""
    title = str(getattr(finding, "title", ""))
    description = str(getattr(finding, "description", ""))
    recommendation = str(getattr(finding, "recommendation", ""))

    title = _replace(
        title,
        "EIP-7702 breaks tx.origin==msg.sender EOA check",
        "EIP-7702 changes tx.origin==msg.sender security assumptions",
    )

    description = _replace(
        description,
        "was used to ensure the caller is a plain EOA without code.",
        "may be used as an EOA-oriented gate, but must not be treated as proof of non-programmable behavior or top-frame-only execution.",
    )
    description = _replace(
        description,
        "Pre-EIP-7702, ETH transfers to EOAs were safe from reentrancy. Post-7702, a delegated EOA has a receive()/fallback() that can execute arbitrary code, including re-entering",
        "A call that sends ETH to a delegated EOA can execute delegated code and may expose callback behavior, including re-entry into",
    )
    description = _replace(
        description,
        "The .transfer() 2300 gas stipend does NOT protect against this — delegation code runs in a separate context.",
        "For `.transfer()` and `.send()`, the normal gas stipend still applies; do not claim arbitrary re-entry is feasible from delegation alone. For `.call{value: ...}` paths, perform a full reentrancy review.",
    )
    description = _replace(
        description,
        "msg.sender becomes the delegation target's address.",
        "nested `delegatecall` preserves the current call-frame sender while executing another implementation in the delegated account's storage context.",
    )
    description = _replace(
        description,
        "msg.sender changes to the delegation target.",
        "nested `delegatecall` preserves the current call-frame sender while executing another implementation in the delegated account's storage context.",
    )

    recommendation = _replace(
        recommendation,
        "Remove `tx.origin == msg.sender` guard entirely — it no longer provides any security guarantee post-EIP-7702.",
        "Do not rely on `tx.origin == msg.sender` as a security boundary for non-programmability, atomic-composability, or reentrancy assumptions. Preserve or remove the check only after documenting its exact purpose.",
    )
    recommendation = _replace(
        recommendation,
        "ensure all authorization checks use tx.origin or a stored owner address rather than msg.sender.",
        "use an explicit stored authorization model and domain-separated signed intent; do not use `tx.origin` as an authorization boundary.",
    )

    check_id = str(getattr(finding, "check_id", ""))
    if check_id == "AA7702-004":
        title = _replace(
            title,
            "EIP-7702 cross-chain delegation replay: chainId=0",
            "EIP-7702 universal authorization policy review: chainId=0",
        )
        description = _replace(
            description,
            "EIP-7702 authorizations with chain_id=0 are valid on ALL EVM chains. An attacker can capture a user's authorization on one chain and replay it on another, delegating the victim's EOA to an attacker-controlled contract on the replay chain.",
            "EIP-7702 intentionally permits `chain_id=0` authorizations for universal deployment. Review whether this broad replay scope is intended and whether the delegated implementation address is safe on every supported chain.",
        )
        recommendation = _replace(
            recommendation,
            "Always use `block.chainid` instead of 0 for chain_id in authorization tuples.",
            "Use `block.chainid` for chain-scoped authorizations. Permit `chain_id=0` only when universal deployment is an explicit, reviewed product requirement.",
        )
        if getattr(finding, "severity", None) == "HIGH":
            finding.severity = "MEDIUM"
        if getattr(finding, "confidence", 0.0) > 0.72:
            finding.confidence = 0.72

    finding.title = title
    finding.description = description
    finding.recommendation = recommendation
    return finding


def install() -> None:
    """Patch EIP7702Finding construction exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return

    try:
        from . import eip7702_detector as detector
    except ImportError:  # direct source-tree imports used by regression tests
        import eip7702_detector as detector

    original = detector.EIP7702Finding.__post_init__
    if getattr(original, "_chainedr_beta_semantics", False):
        _INSTALLED = True
        return

    def patched_post_init(self) -> None:
        normalize_finding_text(self)
        original(self)

    patched_post_init._chainedr_beta_semantics = True
    detector.EIP7702Finding.__post_init__ = patched_post_init
    _INSTALLED = True
