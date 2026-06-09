"""
ChainEDR EIP-7702 Extended Detectors — v2 Extension Module

New checks AA7702-022 through AA7702-026 that were not present in the original
detector. All are novel patterns not covered by Slither, Mythril, or Aderyn.

  AA7702-022  MULTICALL_DELEGATION_LOOP       — multicall atomicity broken by 7702 re-entry
  AA7702-023  GUARDIAN_BYPASS_DELEGATION      — social-recovery guardian assumes EOA
  AA7702-024  ERC4337_AGGREGATOR_COLLISION    — aggregator signature collapses under 7702
  AA7702-025  STALE_DELEGATION_SNAPSHOT       — off-chain delegation snapshot not invalidated
  AA7702-026  PAYMASTER_CONTEXT_CONFUSION     — paymaster reads EOA.code expecting zero
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from .eip7702_detector import EIP7702Finding, _strip_comments, _enclosing_function, _is_in_comment_or_string
except ImportError:
    from eip7702_detector import EIP7702Finding, _strip_comments, _enclosing_function, _is_in_comment_or_string


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-022: Multicall / batch executor broken by delegation re-entry
# ─────────────────────────────────────────────────────────────────────────────
# Many multicall patterns loop over calldata entries and dispatch each via
# call(). If any destination is a 7702-delegated EOA, the EOA's code can
# re-enter the multicall contract mid-batch, observe partially-applied state,
# and manipulate later batch entries.

_MULTICALL_RE = re.compile(
    r"(multicall|batchExecute|executeBatch|multiSend|aggregate|aggregate3"
    r"|_executeMulticall|_multicall)\s*\(",
    re.IGNORECASE,
)
_LOOP_CALL_RE = re.compile(
    r"(for\s*\(|while\s*\().*\.call\s*\{",
    re.DOTALL,
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(nonReentrant|ReentrancyGuard|_locked|_status\s*==\s*_ENTERED)",
)


def detect_multicall_delegation_loop(source: str) -> List[EIP7702Finding]:
    findings: List[EIP7702Finding] = []
    clean = _strip_comments(source)
    lines = source.splitlines()
    seen: set = set()

    for i, line in enumerate(lines):
        m = _MULTICALL_RE.search(line)
        if not m:
            continue
        fn = _enclosing_function(lines, i)
        if fn in seen:
            continue
        # Check the function body for a loop + call pattern
        fn_body_start = i
        for j in range(i, max(i-30, -1), -1):
            if re.match(r"^\s*function\s+", lines[j]):
                fn_body_start = j
                break
        fn_body = "\n".join(lines[fn_body_start:fn_body_start+60])
        has_loop_call = _LOOP_CALL_RE.search(fn_body)
        has_guard = _REENTRANCY_GUARD_RE.search(fn_body)
        if has_loop_call and not has_guard:
            seen.add(fn)
            findings.append(EIP7702Finding(
                check_id="AA7702-022",
                title=f"EIP-7702 multicall re-entry via delegated EOA in {fn}()",
                severity="HIGH",
                description=(
                    f"`{fn}()` iterates calls in a batch without a reentrancy guard. "
                    f"Post-EIP-7702, any call target that is a delegated EOA executes "
                    f"arbitrary code and can re-enter `{fn}()` to observe or modify "
                    f"partially-applied batch state. This breaks atomicity guarantees "
                    f"that multicall implementations rely on."
                ),
                location=f"{fn}():L{i+1}",
                cwe="CWE-362",
                recommendation=(
                    "Add `nonReentrant` to multicall/batch functions. "
                    "Or use a transient-storage lock (EIP-1153 `TSTORE`) "
                    "to gate re-entry within the same transaction cheaply."
                ),
                confidence=0.80,
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-023: Social recovery / guardian assumes EOA
# ─────────────────────────────────────────────────────────────────────────────
# Social recovery schemes (Safe guardians, Argent, etc.) often store a list of
# guardian addresses. Pre-7702, guardians were EOAs, ensuring they could not
# act autonomously. Post-7702, a guardian can delegate to malicious code that
# autonomously signs recovery transactions without the guardian's physical key.

_GUARDIAN_RE = re.compile(
    r"(guardian|recover|social\s*recovery|addGuardian|removeGuardian"
    r"|isGuardian|approveRecovery|executeRecovery)",
    re.IGNORECASE,
)
_EOA_CHECK_RE = re.compile(
    r"(isContract|code\.length|extcodesize|tx\.origin\s*==\s*msg\.sender)",
)


def detect_guardian_eoa_assumption(source: str) -> List[EIP7702Finding]:
    findings: List[EIP7702Finding] = []
    if not _GUARDIAN_RE.search(source):
        return findings
    # If guardians are stored but no EOA check on guardian registration
    lines = source.splitlines()
    add_guardian_lines = [i for i, l in enumerate(lines)
                          if re.search(r"(addGuardian|setGuardian|_guardians\[)", l, re.I)]
    if not add_guardian_lines:
        return findings
    for idx in add_guardian_lines:
        ctx = "\n".join(lines[max(0, idx-5):idx+10])
        has_eoa_check = _EOA_CHECK_RE.search(ctx)
        # Whether or not there's an EOA check, warn: the check is now broken
        fn = _enclosing_function(lines, idx)
        severity = "HIGH" if has_eoa_check else "MEDIUM"
        desc = (
            f"Guardian/recovery system in `{fn}()` "
            + ("uses `isContract/code.length` to verify guardian is EOA — "
               "this check is bypassed post-EIP-7702 (delegated EOAs have non-zero code). "
               if has_eoa_check else
               "adds guardians without verifying they are plain EOAs. ")
            + "A malicious delegation target assigned to a guardian address can "
            "autonomously sign recovery approvals, enabling unauthorized account takeover."
        )
        findings.append(EIP7702Finding(
            check_id="AA7702-023",
            title=f"EIP-7702 breaks guardian EOA assumption in {fn}()",
            severity=severity,
            description=desc,
            location=f"{fn}():L{idx+1}",
            cwe="CWE-284",
            recommendation=(
                "Do not rely on EOA status for guardian security. "
                "Use timelock-gated recovery (minimum 48h delay), "
                "multi-guardian threshold (≥2/3), "
                "and emit events on every recovery action for off-chain monitoring."
            ),
            confidence=0.72,
        ))
        break  # one finding per contract
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-024: ERC-4337 Aggregator signature collision under delegation
# ─────────────────────────────────────────────────────────────────────────────
# ERC-4337 aggregators batch multiple UserOperation signatures into one.
# When the signer is a 7702-delegated EOA, the delegation target's
# `isValidSignature` (ERC-1271) may disagree with the aggregator's on-chain
# ecrecover logic, causing valid operations to be rejected or invalid ones
# to be accepted.

_AGGREGATOR_RE = re.compile(
    r"(ISignatureAggregator|aggregateSignatures|validateSignatures"
    r"|BLSSignatureAggregator|AggregatorStakeInfo)",
    re.IGNORECASE,
)
_ERC4337_AGGREGATOR_CONTEXT_RE = re.compile(
    r"(UserOperation|PackedUserOperation|EntryPoint|validateUserOp"
    r"|handleOps|signatureAggregator|aggregatorStakeInfo|ERC-?4337)",
    re.IGNORECASE,
)
_ERC1271_CHECK_RE = re.compile(
    r"(isValidSignature|ERC1271|IERC1271|0x1626ba7e)",
    re.IGNORECASE,
)


def detect_aggregator_signature_collision(source: str) -> List[EIP7702Finding]:
    findings: List[EIP7702Finding] = []
    if not (_AGGREGATOR_RE.search(source) and _ERC4337_AGGREGATOR_CONTEXT_RE.search(source)):
        return findings
    has_1271 = _ERC1271_CHECK_RE.search(source)
    if has_1271:
        return findings  # Already handles ERC-1271 delegation
    findings.append(EIP7702Finding(
        check_id="AA7702-024",
        title="EIP-7702 aggregator signature collision — missing ERC-1271 path",
        severity="MEDIUM",
        description=(
            "Contract uses an ERC-4337 aggregator but does not check ERC-1271 "
            "`isValidSignature()` on signers. Post-EIP-7702, signers can be "
            "delegated EOAs whose delegation target implements custom signature "
            "validation. The aggregator's raw ecrecover will reject valid "
            "ERC-1271 signatures, breaking UserOperation execution for "
            "7702-delegated accounts."
        ),
        location="contract-level",
        cwe="CWE-347",
        recommendation=(
            "Check if the signer `address.code.length > 0` "
            "(or equivalently, if it is a 7702 delegator) and route signature "
            "validation through `IERC1271.isValidSignature()` in that case. "
            "See ERC-4337 spec §4.4 for aggregator compatibility guidance."
        ),
        confidence=0.68,
    ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-025: Stale off-chain delegation snapshot
# ─────────────────────────────────────────────────────────────────────────────
# Systems that cache or snapshot delegation state off-chain (e.g., governance
# vote snapshots, Merkle airdrop roots, permit caches) may capture a pre-7702
# EOA state. After EIP-7702 activates, the EOA's on-chain code changes but
# the off-chain snapshot remains stale, allowing replay or double-voting.

_SNAPSHOT_RE = re.compile(
    r"(snapshot|merkleRoot|merkle_root|cachedDelegation|storedDelegate"
    r"|_snapshot\[|snapshotId|getVotes\(|getPastVotes\()",
    re.IGNORECASE,
)
_DELEGATION_CONTEXT_RE = re.compile(
    r"(delegat|7702|setCode|EOA|authorize)",
    re.IGNORECASE,
)


def detect_stale_delegation_snapshot(source: str) -> List[EIP7702Finding]:
    findings: List[EIP7702Finding] = []
    if not _SNAPSHOT_RE.search(source):
        return findings
    lines = source.splitlines()
    for i, line in enumerate(lines):
        if _SNAPSHOT_RE.search(line):
            ctx = "\n".join(lines[max(0, i-3):i+5])
            # If snapshot is used in a delegation-sensitive context
            if _DELEGATION_CONTEXT_RE.search(ctx) or _DELEGATION_CONTEXT_RE.search(source):
                fn = _enclosing_function(lines, i)
                findings.append(EIP7702Finding(
                    check_id="AA7702-025",
                    title=f"Stale delegation snapshot may be replayed post-EIP-7702 in {fn}()",
                    severity="MEDIUM",
                    description=(
                        f"`{fn}()` creates or reads a snapshot of delegation/voting "
                        f"state. After EIP-7702, an EOA's code field changes when "
                        f"delegation is set or revoked. Snapshots taken before "
                        f"a delegation change do not reflect the EOA's new on-chain "
                        f"behaviour, enabling stale-snapshot replay (double voting, "
                        f"claiming airdrop as both EOA and delegated account)."
                    ),
                    location=f"{fn}():L{i+1}",
                    cwe="CWE-367",
                    recommendation=(
                        "Invalidate any cached delegation snapshot when `SET_CODE_TX_TYPE` "
                        "transactions are detected for tracked addresses. "
                        "For governance, use block-number gated snapshots and "
                        "verify delegation state at snapshot block, not at claim time."
                    ),
                    confidence=0.65,
                ))
                break
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-026: Paymaster reads EOA.code expecting zero
# ─────────────────────────────────────────────────────────────────────────────
# ERC-4337 Paymasters often distinguish EOA from contract senders to decide
# whether to sponsor gas. A paymaster checking `sender.code.length == 0`
# to "ensure it's an EOA and safe to sponsor" is broken by 7702: the EOA
# now has the 23-byte delegation designator as its code, causing the paymaster
# to reject legitimate 7702 users or to misclassify contract senders.

_PAYMASTER_RE = re.compile(
    r"(IPaymaster|validatePaymasterUserOp|postOp|_validatePaymaster"
    r"|paymaster|Paymaster)",
)
_CODE_LEN_ZERO_RE = re.compile(
    r"(\.code\.length\s*==\s*0|extcodesize\s*\(\s*\w+\s*\)\s*==\s*0"
    r"|isContract\s*\(.*\)\s*==\s*false)",
)


def detect_paymaster_code_check(source: str) -> List[EIP7702Finding]:
    findings: List[EIP7702Finding] = []
    if not _PAYMASTER_RE.search(source):
        return findings
    lines = source.splitlines()
    for i, line in enumerate(lines):
        m = _CODE_LEN_ZERO_RE.search(line)
        if not m:
            continue
        fn = _enclosing_function(lines, i)
        findings.append(EIP7702Finding(
            check_id="AA7702-026",
            title=f"EIP-7702 breaks Paymaster EOA detection in {fn}()",
            severity="HIGH",
            description=(
                f"Paymaster `{fn}()` checks `code.length == 0` to determine if the "
                f"sender is an EOA. Post-EIP-7702, every delegated EOA has a 23-byte "
                f"delegation designator as its code, so this check returns `false` for "
                f"all 7702 users. The paymaster will either refuse to sponsor 7702 "
                f"accounts (DoS) or — if the logic is inverted — will sponsor "
                f"arbitrary contracts (security bypass)."
            ),
            location=f"{fn}():L{i+1}",
            cwe="CWE-697",
            recommendation=(
                "Remove `code.length == 0` as the EOA test in paymasters. "
                "Instead, check if `sender.code` starts with `0xef0100` "
                "(the EIP-7702 delegation designator prefix) to distinguish "
                "7702-delegated EOAs from regular contracts. "
                "Or use ERC-4337 v0.7+ AccountFactory registry which handles this."
            ),
            confidence=0.85,
        ))
        break
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_extended_checks(source: str) -> List[EIP7702Finding]:
    """Run all AA7702-022 to AA7702-026 extended checks on a Solidity source."""
    findings: List[EIP7702Finding] = []
    findings.extend(detect_multicall_delegation_loop(source))
    findings.extend(detect_guardian_eoa_assumption(source))
    findings.extend(detect_aggregator_signature_collision(source))
    findings.extend(detect_stale_delegation_snapshot(source))
    findings.extend(detect_paymaster_code_check(source))
    return findings
