"""
ChainEDR ERC-4337 Account Abstraction Checker

Static analysis for ERC-4337 / Account Abstraction vulnerabilities.
No existing ChainEDR module covers this attack surface.

Checks:
  BUNDLER_GRIEFING     — validateUserOp reverts instead of returning magic value
  PAYMASTER_DRAIN      — validatePaymasterUserOp ignores sender/callData
  SIGNATURE_BYPASS     — validateUserOp never calls ECDSA.recover / isValidSignature
  FACTORY_FRONTRUN     — initCode deployment is not sender-bound
  NONCE_SKIP           — nonce validation allows non-monotonic values
  GAS_ESTIMATION_BYPASS— verificationGasLimit can be 0

Reference: ERC-4337 spec https://eips.ethereum.org/EIPS/eip-4337
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ERC4337Finding:
    check_id: str
    title: str
    severity: str
    description: str
    function: str
    recommendation: str


# ─────────────────────────────────────────────────────────────────────────────
# Regex helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_function_body(source: str, fn_name: str) -> str:
    """
    Extract the body of a Solidity function by name.
    Handles nested braces. Returns empty string if not found.
    """
    pattern = re.compile(
        r"\bfunction\s+" + re.escape(fn_name) + r"\b[^{]*\{",
        re.DOTALL,
    )
    m = pattern.search(source)
    if not m:
        return ""
    start = m.end() - 1  # position of opening brace
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
    return source[start:]


def _strip_comments(source: str) -> str:
    """Remove // and /* */ comments from Solidity source."""
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return source


def _fn_names_from_abi(abi: List[Dict]) -> Set[str]:
    return {e.get("name", "") for e in abi if e.get("type") == "function"}


# ─────────────────────────────────────────────────────────────────────────────
# ERC-4337 Checker
# ─────────────────────────────────────────────────────────────────────────────

class ERC4337Checker:
    """
    Static + ABI-level checks for ERC-4337 Account Abstraction vulnerabilities.

    Call .check(source, abi) to run all checks.
    Call .is_erc4337(source, abi) first to skip non-AA contracts.
    """

    # Key function selectors (keccak256 truncated to 4 bytes)
    SELECTOR_VALIDATE_USER_OP        = "0x3a871cdd"
    SELECTOR_VALIDATE_PAYMASTER_OP   = "0x52b7512c"
    SELECTOR_GET_DEPOSIT             = "0xc399ec88"

    # EIP-4337 magic return value for valid signatures
    SIG_VALIDATION_SUCCESS = "0"
    SIG_VALIDATION_FAILED  = "1"

    AA_FUNCTIONS: Set[str] = {
        "validateUserOp",
        "validatePaymasterUserOp",
        "executeUserOp",
        "getDeposit",
        "addStake",
        "unlockStake",
        "withdrawStake",
        "getNonce",
        "entryPoint",
    }

    # ── Public API ────────────────────────────────────────────────────────────

    def is_erc4337(self, source: str, abi: List[Dict]) -> bool:
        """
        Returns True if contract is likely an ERC-4337 component.
        Heuristics: ABI contains validateUserOp, or source references
        IEntryPoint / UserOperation / PackedUserOperation.
        """
        abi_names = _fn_names_from_abi(abi)
        if "validateUserOp" in abi_names or "validatePaymasterUserOp" in abi_names:
            return True
        aa_keywords = re.compile(
            r"(IEntryPoint|UserOperation|PackedUserOperation|IAccount\b"
            r"|IPaymaster\b|EntryPoint\b|handleOps|handleAggregatedOps"
            r"|SIG_VALIDATION_FAILED|SIG_VALIDATION_SUCCESS)",
            re.IGNORECASE,
        )
        return bool(aa_keywords.search(source))

    def check(self, source: str, abi: List[Dict]) -> List[ERC4337Finding]:
        """Run all checks. Returns list of findings (may be empty)."""
        clean = _strip_comments(source)
        findings: List[ERC4337Finding] = []

        checks = [
            self._check_bundler_griefing,
            self._check_paymaster_validation,
            self._check_signature_bypass,
            self._check_factory_frontrun,
            self._check_nonce_validation,
            self._check_gas_estimation_bypass,
        ]
        for fn in checks:
            result = fn(clean)
            if result:
                findings.append(result)

        return findings

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_bundler_griefing(self, source: str) -> Optional[ERC4337Finding]:
        """
        ERC-4337 §6.1: validateUserOp MUST NOT revert — it must return
        SIG_VALIDATION_FAILED (1) on bad signature.
        If the function body contains revert/require but no return of
        SIG_VALIDATION_FAILED, bundlers get griefed (gas lost, no refund).
        """
        body = _extract_function_body(source, "validateUserOp")
        if not body:
            return None

        has_revert  = bool(re.search(r"\b(revert|require)\s*\(", body))
        has_magic   = bool(re.search(
            r"(SIG_VALIDATION_FAILED|return\s+1\b|ValidationData)", body
        ))

        if has_revert and not has_magic:
            return ERC4337Finding(
                check_id="AA-001",
                title="Bundler Griefing: validateUserOp reverts on failure",
                severity="HIGH",
                description=(
                    "validateUserOp uses revert/require instead of returning "
                    "SIG_VALIDATION_FAILED (1). A malicious user can craft a UserOp "
                    "that passes off-chain simulation but reverts on-chain, causing "
                    "bundlers to lose gas with no reimbursement."
                ),
                function="validateUserOp",
                recommendation=(
                    "Replace revert/require inside validateUserOp with "
                    "`return SIG_VALIDATION_FAILED` (return 1). "
                    "Only revert for system-level errors unrelated to the user's signature."
                ),
            )
        return None

    def _check_paymaster_validation(self, source: str) -> Optional[ERC4337Finding]:
        """
        ERC-4337 §7: validatePaymasterUserOp must validate userOp.sender
        and userOp.callData to prevent unauthorized gas sponsorship.
        Missing checks allow any caller to drain the paymaster deposit.
        """
        body = _extract_function_body(source, "validatePaymasterUserOp")
        if not body:
            return None

        # Look for references to sender and callData inside the validation body
        checks_sender   = bool(re.search(r"\buserOp\.(sender|from)\b", body))
        checks_calldata = bool(re.search(r"\buserOp\.(callData|data)\b", body))
        # A body that just returns (context, 0) with no validation
        trivial_return  = bool(re.match(r"\s*\{\s*return\s*\(", body.strip()))

        if trivial_return or (not checks_sender and not checks_calldata):
            return ERC4337Finding(
                check_id="AA-002",
                title="Paymaster Drain: validatePaymasterUserOp ignores sender/callData",
                severity="HIGH",
                description=(
                    "validatePaymasterUserOp does not inspect userOp.sender or "
                    "userOp.callData. Any arbitrary UserOp can be sponsored, allowing "
                    "an attacker to drain the paymaster's EntryPoint deposit by submitting "
                    "expensive operations targeting unrelated contracts."
                ),
                function="validatePaymasterUserOp",
                recommendation=(
                    "Validate userOp.sender against an allowlist or require "
                    "userOp.callData to match an approved selector. "
                    "Consider a per-sender gas cap or a signature from a trusted signer."
                ),
            )
        return None

    def _check_signature_bypass(self, source: str) -> Optional[ERC4337Finding]:
        """
        validateUserOp must cryptographically verify the user's signature.
        If ECDSA.recover / ecrecover / isValidSignature is absent, any
        UserOp passes validation — attacker can execute arbitrary callData.
        """
        body = _extract_function_body(source, "validateUserOp")
        if not body:
            return None

        has_sig_check = bool(re.search(
            r"(ECDSA\.recover|ecrecover\s*\(|isValidSignature\s*\("
            r"|SignatureChecker|_isValidSignature)",
            body,
        ))
        # If function body is short and just returns 0 — definitely no check
        body_stripped = re.sub(r"\s+", " ", body).strip()
        trivial       = bool(re.match(r"\{ return\s+0\s*;?\s*\}", body_stripped))

        if not has_sig_check or trivial:
            return ERC4337Finding(
                check_id="AA-003",
                title="Signature Bypass: validateUserOp missing ECDSA verification",
                severity="CRITICAL",
                description=(
                    "validateUserOp does not call ECDSA.recover, ecrecover, or "
                    "isValidSignature. An attacker can submit a UserOp with an arbitrary "
                    "signature and have it accepted, allowing execution of any callData "
                    "on behalf of the account — including self-destruct or asset transfers."
                ),
                function="validateUserOp",
                recommendation=(
                    "Call ECDSA.recover(userOpHash, userOp.signature) and compare "
                    "against the account owner. Return SIG_VALIDATION_FAILED (1) on "
                    "mismatch. Never return 0 unconditionally."
                ),
            )
        return None

    def _check_factory_frontrun(self, source: str) -> Optional[ERC4337Finding]:
        """
        initCode execution (factory call in UserOp) must deploy to an address
        that only the legitimate owner can claim. If the factory uses CREATE
        instead of CREATE2 with a user-controlled salt, an attacker can front-run
        the deployment and take ownership of the predicted address.
        """
        # Look for factory/initCode patterns
        has_init_code = bool(re.search(
            r"(initCode|createAccount|deployAccount|factory\.create)",
            source, re.IGNORECASE,
        ))
        if not has_init_code:
            return None

        uses_create2 = bool(re.search(r"\bcreate2\b|\bCREATE2\b", source, re.IGNORECASE))
        # If using CREATE2 with owner/salt derived from msg.sender — OK
        owner_salt   = bool(re.search(
            r"(salt\s*=.*owner|salt\s*=.*sender|keccak256.*owner)", source, re.IGNORECASE
        ))

        if not uses_create2 or not owner_salt:
            return ERC4337Finding(
                check_id="AA-004",
                title="Factory Frontrun: initCode deployment not sender-bound",
                severity="MEDIUM",
                description=(
                    "The account factory uses CREATE or CREATE2 without tying the salt "
                    "to the intended owner's address. An attacker monitoring the mempool "
                    "can front-run the initCode call, deploying a controlled contract to "
                    "the same address and stealing the account before the victim."
                ),
                function="factory / initCode",
                recommendation=(
                    "Use CREATE2 with salt = keccak256(abi.encode(owner, nonce)). "
                    "Verify inside the account constructor that msg.sender matches "
                    "the expected factory and the owner is set atomically."
                ),
            )
        return None

    def _check_nonce_validation(self, source: str) -> Optional[ERC4337Finding]:
        """
        ERC-4337 §2.4: nonces must be monotonically increasing per key.
        Accepting gaps (e.g., `nonce >= lastNonce`) or using a non-sequential
        scheme without proper key isolation opens replay / ordering attacks.
        """
        body = _extract_function_body(source, "validateUserOp")
        nonce_body = body or source  # fall back to full source if no isolated fn

        # Non-sequential nonce acceptance patterns
        gap_patterns = re.compile(
            r"(nonce\s*>=\s*\w+|nonce\s*>\s*\w+(?!\s*\+\s*1)"
            r"|require\s*\(\s*nonce\s*>=)",
            re.IGNORECASE,
        )
        missing_nonce = not re.search(r"\bnonce\b", nonce_body, re.IGNORECASE)

        if missing_nonce:
            return ERC4337Finding(
                check_id="AA-005",
                title="Nonce Skip: validateUserOp does not validate nonce",
                severity="HIGH",
                description=(
                    "validateUserOp does not reference userOp.nonce. "
                    "Without nonce validation, the same UserOp can be replayed "
                    "after execution, or UserOps can be reordered to exploit "
                    "intermediate states."
                ),
                function="validateUserOp",
                recommendation=(
                    "Delegate nonce validation to EntryPoint via "
                    "`entryPoint.validateNonce(userOp.nonce)` or maintain "
                    "a per-key monotonic nonce mapping and revert on out-of-order values."
                ),
            )

        if gap_patterns.search(nonce_body):
            return ERC4337Finding(
                check_id="AA-005",
                title="Nonce Skip: non-monotonic nonce validation",
                severity="MEDIUM",
                description=(
                    "Nonce check uses >= or > instead of == (expected next nonce). "
                    "Allows skipping nonce values, creating replay and ordering attacks "
                    "on UserOps within the skipped range."
                ),
                function="validateUserOp",
                recommendation=(
                    "Enforce strict equality: `require(userOp.nonce == _nonces[sender]++)`."
                ),
            )

        return None

    def _check_gas_estimation_bypass(self, source: str) -> Optional[ERC4337Finding]:
        """
        ERC-4337 §10: if verificationGasLimit is not lower-bounded,
        an attacker can set it to 0 and bypass the gas estimation check
        used by bundlers to pre-validate UserOps off-chain.
        """
        # Look for verificationGasLimit without a minimum check
        has_vgl = bool(re.search(r"verificationGasLimit", source, re.IGNORECASE))
        if not has_vgl:
            return None

        has_min_check = bool(re.search(
            r"(verificationGasLimit\s*[>]=?\s*\d"
            r"|require.*verificationGasLimit"
            r"|MIN_VERIFICATION_GAS"
            r"|verificationGasLimit\s*!=\s*0)",
            source, re.IGNORECASE,
        ))

        if not has_min_check:
            return ERC4337Finding(
                check_id="AA-006",
                title="Gas Estimation Bypass: verificationGasLimit not lower-bounded",
                severity="MEDIUM",
                description=(
                    "verificationGasLimit is used but not checked for a minimum value. "
                    "A UserOp with verificationGasLimit=0 passes off-chain simulation "
                    "but causes on-chain validation to run out of gas silently, "
                    "griefing bundlers and bypassing expected gas accounting."
                ),
                function="validateUserOp",
                recommendation=(
                    "Add: `require(userOp.verificationGasLimit >= MIN_VERIFICATION_GAS, "
                    "'AA: gas limit too low')` before executing validation logic. "
                    "MIN_VERIFICATION_GAS should be at least the cost of ECDSA.recover."
                ),
            )

        return None
