"""
ChainEDR ERC-7821 Batch Execution Security Checker

ERC-7821 (Minimal Batch Executor Interface) was finalized alongside EIP-7702
in the Pectra upgrade. It defines a standard `execute(bytes32 mode, bytes calldata)` 
interface for smart accounts to process batched calls. This module detects
security issues specific to ERC-7821 implementations.

Checks:
  ERC7821-001  MODE_NOT_VALIDATED         — execute() accepts unknown mode bytes silently
  ERC7821-002  OPDATA_LENGTH_NOT_CHECKED  — opData field trusted without length guard
  ERC7821-003  BATCH_REVERT_SILENT        — sub-call failures swallowed, not propagated
  ERC7821-004  DELEGATECALL_MODE_EXPOSED  — mode byte 0x01 delegates to arbitrary target
  ERC7821-005  VALUE_ACCOUNTING_BATCH     — msg.value split logic integer underflow risk
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List


@dataclass
class ERC7821Finding:
    check_id: str
    title: str
    severity: str
    description: str
    location: str
    recommendation: str
    confidence: float


# Mode byte constants from ERC-7821 spec
_EXECUTE_RE = re.compile(
    r"function\s+execute\s*\(\s*bytes32\s+\w*mode\w*",
    re.IGNORECASE,
)
_MODE_VALIDATE_RE = re.compile(
    r"(mode\s*==|_validateMode|_checkMode|supportedModes|_isSupportedMode"
    r"|require.*mode|if.*mode)",
    re.IGNORECASE,
)
_REVERT_PROPAGATE_RE = re.compile(
    r"(revert\s+ExecutionFailed|assembly\s*\{[^}]*revert|if\s*!\s*success\s*\{[^}]*revert"
    r"|if\s*\(\s*!success\s*\))",
)
_SILENT_SWALLOW_RE = re.compile(
    r"\(bool\s+\w+,\s*\)\s*=\s*\w+\.call\s*\{[^}]*\}[^;]*;(?!\s*(require|if|assert))",
)
_DELEGATECALL_MODE_RE = re.compile(
    r"(0x01000000[0-9a-f]*|delegatecall.*mode|mode.*delegatecall)",
    re.IGNORECASE,
)
_VALUE_SPLIT_RE = re.compile(
    r"(msg\.value\s*[-/]\s*\w+|value\s*[-/]\s*amounts\[|totalValue\s*-=)",
)
_BATCH_RE = re.compile(
    r"(Call\[\]|Execution\[\]|calls\s*=\s*abi\.decode|_executeBatch|_execute\s*\()",
)


def check_erc7821(source: str) -> List[ERC7821Finding]:
    """Run all ERC-7821 security checks."""
    if not _EXECUTE_RE.search(source) and not _BATCH_RE.search(source):
        return []

    findings: List[ERC7821Finding] = []
    lines = source.splitlines()

    # ERC7821-001: Mode not validated
    has_execute = _EXECUTE_RE.search(source)
    has_mode_check = _MODE_VALIDATE_RE.search(source)
    if has_execute and not has_mode_check:
        findings.append(ERC7821Finding(
            check_id="ERC7821-001",
            title="ERC-7821 execute() accepts unknown mode bytes without validation",
            severity="HIGH",
            description=(
                "The `execute(bytes32 mode, bytes calldata)` function does not "
                "validate the `mode` parameter against a list of supported modes. "
                "ERC-7821 defines multiple execution modes (CALL=0x00, DELEGATECALL=0x01, "
                "STATICCALL=0x02, etc.). Accepting unknown mode bytes can cause undefined "
                "behaviour, enable privilege escalation via delegatecall mode injection, "
                "or silently no-op critical batch operations."
            ),
            location="execute():mode-parameter",
            recommendation=(
                "Add `if (!_isSupportedMode(mode)) revert UnsupportedExecutionMode();` "
                "at the top of `execute()`. Maintain an explicit `supportedModes` bitmap "
                "and reject any mode outside it."
            ),
            confidence=0.82,
        ))

    # ERC7821-002: opData length not checked
    op_data_re = re.compile(r"opData|callData\s*=\s*abi\.decode|_decodeOp", re.I)
    length_check_re = re.compile(r"(\.length\s*[><=!]|require.*\.length|if.*\.length)")
    if op_data_re.search(source) and not length_check_re.search(source):
        findings.append(ERC7821Finding(
            check_id="ERC7821-002",
            title="ERC-7821 opData field decoded without length guard",
            severity="MEDIUM",
            description=(
                "Batch execution decodes `opData` or call structs from calldata "
                "without checking array/bytes length bounds. An attacker supplying "
                "malformed calldata can cause out-of-bounds reads (panic), "
                "or skip authorization checks if the decode silently truncates."
            ),
            location="execute():opData-decode",
            recommendation=(
                "Validate `calls.length > 0` and `calls.length <= MAX_BATCH_SIZE` "
                "before processing. Use `abi.decode` with explicit type bounds "
                "and wrap in try/catch for untrusted input."
            ),
            confidence=0.70,
        ))

    # ERC7821-003: Batch revert silently swallowed
    for i, line in enumerate(lines):
        m = _SILENT_SWALLOW_RE.search(line)
        if m:
            ctx = "\n".join(lines[i:min(i+5, len(lines))])
            if not _REVERT_PROPAGATE_RE.search(ctx):
                findings.append(ERC7821Finding(
                    check_id="ERC7821-003",
                    title=f"ERC-7821 batch sub-call failure silently swallowed at L{i+1}",
                    severity="HIGH",
                    description=(
                        f"A `.call()` return value at line {i+1} is captured but the "
                        f"failure is not propagated via `revert`. In ERC-7821 batch mode, "
                        f"silent swallowing means a failed sub-call is treated as success, "
                        f"allowing partial execution that corrupts invariants "
                        f"(e.g., token transferred out but state update skipped)."
                    ),
                    location=f"L{i+1}",
                    recommendation=(
                        "After every `.call()`, either `require(success, 'CallFailed')` "
                        "or use `assembly { if iszero(success) { revert(0,0) } }`. "
                        "For intentionally-optional calls, document clearly and ensure "
                        "no state change precedes the call."
                    ),
                    confidence=0.75,
                ))
            break

    # ERC7821-004: Delegatecall mode exposed to untrusted callers
    if _DELEGATECALL_MODE_RE.search(source):
        access_check = re.compile(
            r"(onlyOwner|onlyEntryPoint|msg\.sender\s*==|require.*sender|_checkCaller)",
            re.I,
        )
        if not access_check.search(source):
            findings.append(ERC7821Finding(
                check_id="ERC7821-004",
                title="ERC-7821 delegatecall mode exposed without access control",
                severity="CRITICAL",
                description=(
                    "The batch executor supports `delegatecall` mode (0x01) but "
                    "does not restrict who can call `execute()`. Any caller can "
                    "delegatecall an arbitrary target in the account's storage context, "
                    "overwriting owner, nonce, or balance storage slots. This is "
                    "equivalent to an unrestricted `delegatecall` exploit."
                ),
                location="execute():delegatecall-mode",
                recommendation=(
                    "Gate delegatecall mode execution behind strict access control: "
                    "`require(msg.sender == entryPoint() || msg.sender == owner())`. "
                    "Consider disabling delegatecall mode entirely unless explicitly required."
                ),
                confidence=0.88,
            ))

    # ERC7821-005: Value accounting integer underflow in batch
    for i, line in enumerate(lines):
        if _VALUE_SPLIT_RE.search(line):
            if re.search(r"unchecked\s*\{", "\n".join(lines[max(0,i-3):i+3])):
                findings.append(ERC7821Finding(
                    check_id="ERC7821-005",
                    title=f"ERC-7821 batch value split in unchecked block — underflow risk at L{i+1}",
                    severity="HIGH",
                    description=(
                        f"ETH value is split or subtracted across batch calls inside "
                        f"an `unchecked` block at line {i+1}. If the sum of batch call "
                        f"values exceeds `msg.value`, the subtraction underflows silently "
                        f"(no panic in unchecked), and remaining calls receive inflated "
                        f"value from the contract's own ETH balance — a fund-drain vector."
                    ),
                    location=f"L{i+1}",
                    recommendation=(
                        "Move value accounting outside `unchecked` blocks. "
                        "Use `totalValue += calls[i].value` first, then "
                        "`require(totalValue == msg.value)` before dispatch."
                    ),
                    confidence=0.78,
                ))
            break

    return findings
