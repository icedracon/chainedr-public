import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import beta_semantics  # noqa: E402
from eip7702_detector import EIP7702Finding  # noqa: E402


def _finding(check_id: str, description: str, recommendation: str = "") -> EIP7702Finding:
    return EIP7702Finding(
        check_id=check_id,
        title="title",
        severity="HIGH",
        description=description,
        location="Target.sol:L1",
        cwe="CWE-000",
        recommendation=recommendation,
        confidence=0.95,
    )


def test_callback_wording_keeps_transfer_stipend_semantics():
    finding = _finding(
        "AA7702-003",
        "The .transfer() 2300 gas stipend does NOT protect against this — delegation code runs in a separate context.",
    )
    beta_semantics.normalize_finding_text(finding)
    assert "normal gas stipend still applies" in finding.description
    assert "delegation code runs in a separate context" not in finding.description


def test_chain_id_zero_is_policy_review_not_automatic_high_severity_bug():
    finding = _finding(
        "AA7702-004",
        "EIP-7702 authorizations with chain_id=0 are valid on ALL EVM chains. An attacker can capture a user's authorization on one chain and replay it on another, delegating the victim's EOA to an attacker-controlled contract on the replay chain.",
        "Always use `block.chainid` instead of 0 for chain_id in authorization tuples.",
    )
    finding.title = "EIP-7702 cross-chain delegation replay: chainId=0 in auth()"
    beta_semantics.normalize_finding_text(finding)
    assert finding.severity == "MEDIUM"
    assert finding.confidence == 0.72
    assert "universal authorization policy review" in finding.title
    assert "intentionally permits `chain_id=0`" in finding.description


def test_delegatecall_recommendation_does_not_suggest_tx_origin_authorization():
    finding = _finding(
        "AA7702-006",
        "msg.sender becomes the delegation target's address.",
        "ensure all authorization checks use tx.origin or a stored owner address rather than msg.sender.",
    )
    beta_semantics.normalize_finding_text(finding)
    assert "preserves the current call-frame sender" in finding.description
    assert "do not use `tx.origin`" in finding.recommendation


def test_installer_is_idempotent():
    beta_semantics.install()
    first = EIP7702Finding.__post_init__
    beta_semantics.install()
    assert EIP7702Finding.__post_init__ is first
