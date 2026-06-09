"""Auditor-grade normalization for EIP-7702 finding text.

The detector intentionally stays conservative and pattern-oriented.  This
private-beta layer corrects report wording where an early prototype phrasing
could overstate EVM semantics or recommend an unsafe authorization shortcut.

It changes report text only.  It does not change rule matching, severity, or
confidence scores.
"""

from __future__ import annotations

from typing import Callable

_INSTALLED = False


def _replace(text: str, old: str, new: str) -> str:
    return text.replace(old, new) if old in text else text


def normalize_finding(finding) -> None:
    """Normalize a single EIP-7702 finding in place."""
    if finding.check_id == "AA7702-003":
        finding.description = _replace(
            finding.description,
            "The .transfer() 2300 gas stipend does NOT protect against this — delegation code runs in a separate context.",
            "Low-level call{value: ...} can forward enough gas for callbacks. transfer()/send() still impose a stipend, but must not be treated as a complete authorization, liveness, or reentrancy boundary. Use checks-effects-interactions and a reentrancy guard where state can be affected.",
        )

    if finding.check_id == "AA7702-006":
        finding.description = _replace(
            finding.description,
            "A nested delegatecall creates double context confusion: the inner call's code accesses the EOA's storage and balance, but msg.sender changes to the delegation target. This can break authorization checks that rely on msg.sender == owner.",
            "A nested delegatecall executes the inner implementation's code against the delegated account's storage and balance. delegatecall preserves msg.sender and msg.value across the hop, so the core risk is storage-layout confusion, implementation trust, and unexpected delegated-account authority rather than a msg.sender rewrite.",
        )
        finding.recommendation = _replace(
            finding.recommendation,
            "Use regular call() instead, or if delegatecall is required, ensure all authorization checks use tx.origin or a stored owner address rather than msg.sender.",
            "Prefer regular call() when delegated storage execution is unnecessary. If delegatecall is required, do not replace authorization with tx.origin. Use an explicit authority model, allowlisted implementations, namespaced storage, nonce and domain separation, and EIP-712/EIP-1271-compatible validation where applicable.",
        )


def install() -> None:
    """Patch EIP7702Finding construction exactly once."""
    global _INSTALLED
    if _INSTALLED:
        return

    try:
        from . import eip7702_detector as detector
    except ImportError:  # direct source-tree usage
        import eip7702_detector as detector

    original_post_init: Callable = detector.EIP7702Finding.__post_init__

    def hardened_post_init(self) -> None:
        normalize_finding(self)
        original_post_init(self)

    detector.EIP7702Finding.__post_init__ = hardened_post_init
    _INSTALLED = True
