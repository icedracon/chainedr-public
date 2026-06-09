"""
ChainEDR False Positive Filter — Module 8

Runs AFTER Classifier, BEFORE Reporter.
Does NOT modify the core pipeline — adds metadata tags only.

Every finding is preserved. FP tags are advisory:
  - is_likely_fp: bool
  - fp_reasons: List[FPReason]
  - fp_confidence: float  (0.0 = definitely real, 1.0 = definitely FP)
  - recommended_action: "SUBMIT" | "REVIEW" | "SKIP"

Design principle: Non-destructive. The researcher always sees the finding.
The filter only explains WHY it might be rejected before you submit.

Covers 15 global FP categories sourced from real audit rejection patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


# ─── DATA STRUCTURES ─────────────────────────────────────────────────────────

@dataclass
class FPReason:
    rule_id: str          # e.g. "TRUST_MODEL"
    rule_name: str        # human-readable
    explanation: str      # why this specific finding may be FP
    fp_weight: float      # 0.0–1.0 contribution to fp_confidence
    evidence: str = ""    # what in the finding triggered this rule


@dataclass
class FPVerdict:
    is_likely_fp: bool
    fp_confidence: float        # 0.0 = real bug, 1.0 = definitely FP
    fp_reasons: List[FPReason]
    recommended_action: str     # "SUBMIT" | "REVIEW" | "SKIP"
    adjusted_severity: str      # may be downgraded
    submit_notes: str           # what to add/fix before submitting

    def summary(self) -> str:
        if not self.fp_reasons:
            return "✓ No FP flags — looks clean to submit."
        lines = [f"⚠ FP confidence: {self.fp_confidence:.0%} → {self.recommended_action}"]
        for r in self.fp_reasons:
            lines.append(f"  [{r.rule_id}] {r.rule_name}: {r.explanation}")
        if self.submit_notes:
            lines.append(f"  → {self.submit_notes}")
        return "\n".join(lines)


# ─── CONTEXT OBJECT (passed to filter alongside the finding) ─────────────────

@dataclass
class AuditContext:
    """
    Everything ChainEDR knows about the contract being audited.
    Pass as much as you have — all fields are optional.
    """
    # Source / compilation
    solidity_version: str = ""          # e.g. "0.8.19"
    source_code: str = ""               # full flattened source (if available)
    function_source: str = ""           # source of the specific flagged function
    abi: List[Dict] = field(default_factory=list)

    # Access control
    function_modifiers: List[str] = field(default_factory=list)
    # e.g. ["onlyOwner", "onlyApprovedMigrator", "nonReentrant"]

    # Protocol design intent
    explicitly_supports_fot_tokens: bool = False   # fee-on-transfer tokens
    explicitly_supports_rebasing: bool = False
    explicitly_supports_erc777: bool = False
    has_flash_loan_feature: bool = False            # protocol OFFERS flash loans
    has_pause_mechanism: bool = False
    has_rescue_function: bool = False
    has_upgrade_mechanism: bool = False

    # Token context
    token_whitelist_enforced: bool = False          # protocol restricts which tokens
    expected_token_standard: str = "ERC20"         # "ERC20" | "ANY" | "NATIVE"

    # Finding context
    flagged_function_sig: str = ""
    flagged_function_is_view: bool = False
    flagged_parameter_name: str = ""               # e.g. "lockDuration"
    flagged_parameter_value: Any = None            # e.g. 0

    # Other findings in same session (for dependency detection)
    other_finding_titles: List[str] = field(default_factory=list)

    # File path of the contract being analysed (for test-file exclusion)
    filepath: str = ""


# ─── THE FILTER ──────────────────────────────────────────────────────────────

class FalsePositiveFilter:
    """
    Analyses a classified vulnerability against 15 global FP categories.

    Usage:
        ctx = AuditContext(
            solidity_version="0.8.19",
            function_modifiers=["onlyOwner"],
            ...
        )
        verdict = FalsePositiveFilter().analyse(vuln_dict, ctx)
        print(verdict.summary())
    """

    # Weight thresholds
    SUBMIT_THRESHOLD = 0.25   # fp_confidence < this → SUBMIT
    REVIEW_THRESHOLD = 0.55   # fp_confidence < this → REVIEW (else SKIP)

    # Severity order for downgrading
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

    # ── Access control modifiers that imply a TRUSTED caller ─────────────────
    PRIVILEGED_MODIFIERS = {
        "onlyOwner", "onlyAdmin", "onlyGovernance", "onlyOperator",
        "onlyApprovedMigrator", "onlyMinter", "onlyBurner", "onlyVault",
        "onlyRole", "onlyController", "onlyTimelock", "onlyGuardian",
        "requiresAuth", "adminOnly", "ownerOnly", "managerOnly",
        "onlyProtocol", "onlyFactory", "onlyRouter", "onlyRegistry",
        "onlyWhitelisted", "onlyKYC", "onlyRelayer", "onlyOracle",
    }

    # ── Modifiers that indicate reentrancy protection ─────────────────────────
    REENTRANCY_GUARD_MODIFIERS = {
        "nonReentrant", "noReentrancy", "reentrancyGuard",
        "nonReentrantBefore", "nonReentrantAfter",
    }

    # ── Non-standard token patterns in source ────────────────────────────────
    FOT_PATTERNS = [
        r"fee.?on.?transfer", r"transfer.?fee", r"deflation",
        r"tax.?token", r"feePercent", r"burnOnTransfer",
    ]
    REBASE_PATTERNS = [
        r"rebas",          # rebase / rebasing / rebased
        r"elastic supply", r"AMPL\b", r"stETH", r"aToken",
    ]
    ERC777_PATTERNS = [
        r"tokensToSend", r"tokensReceived", r"ERC777", r"_send\(",
    ]

    # ── Remainder-capture patterns ────────────────────────────────────────────
    REMAINDER_PATTERNS = [
        # "last share = total - sum of others" idiom
        r"=\s*\w+\s*-\s*\w+\s*-\s*\w+",           # x = total - a - b
        r"remainder\s*=", r"dust\s*=",
        r"balance0\s*\+=", r"balance1\s*\+=",
        r"beneficiaryFees\d*\s*[+]?=",
        r"residual", r"leftover",
    ]

    # ── Solidity 0.8+ implicit arithmetic protection ──────────────────────────
    SOL08_ARITHMETIC_VULN_TYPES = {
        "INTEGER_OVERFLOW", "ARITHMETIC_OVERFLOW", "UNDERFLOW",
        "MISSING_BOUNDS_CHECK",
    }

    # ── Flash loan provider addresses (from classifier) ───────────────────────
    FLASH_LOAN_PROVIDERS_LOWER = {
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # AAVE V3
        "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # AAVE V2
        "0xba12222222228d8ba445958a75a0704d566bf2c8",  # Balancer
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3
    }

    # ── Rescue / recovery function name patterns ──────────────────────────────
    RESCUE_PATTERNS = [
        r"rescue", r"recover", r"sweep", r"emergency",
        r"withdrawStuck", r"recoverERC20", r"adminWithdraw",
    ]

    def __init__(self, enabled_rules: Optional[List[str]] = None):
        """
        Args:
            enabled_rules: If None, ALL rules are enabled.
                           Pass a list of rule IDs to run only those.
        """
        self.enabled_rules = set(enabled_rules) if enabled_rules else None

    def _rule_enabled(self, rule_id: str) -> bool:
        return self.enabled_rules is None or rule_id in self.enabled_rules

    @staticmethod
    def _desc(vuln: Dict[str, Any]) -> str:
        """Return lowercased combined text from all description-like fields."""
        return " ".join([
            vuln.get("description", ""),
            vuln.get("anomaly_description", ""),
            vuln.get("attack_vector", ""),
            " ".join(vuln.get("reasons", [])),
        ]).lower()

    # ─── PUBLIC API ──────────────────────────────────────────────────────────

    def analyse(
        self,
        vuln: Dict[str, Any],
        ctx: AuditContext
    ) -> FPVerdict:
        """
        Run all FP rules against a classified vulnerability.

        Args:
            vuln: Dict from ClassifiedVulnerability.to_dict() (or any dict
                  with keys: vulnerability_type, severity, description,
                  fix_recommendation, confidence)
            ctx:  AuditContext with everything known about the contract

        Returns:
            FPVerdict with full analysis
        """
        reasons: List[FPReason] = []

        # Run all 15 rules
        rules = [
            self._rule_trust_model,
            self._rule_nonstandard_token,
            self._rule_sol08_implicit_protection,
            self._rule_remainder_handled,
            self._rule_reentrancy_guard,
            self._rule_secondary_condition_dependency,
            self._rule_view_function_only,
            self._rule_legitimate_flash_loan_feature,
            self._rule_proxy_delegatecall,
            self._rule_dust_below_threshold,
            self._rule_admin_rescue_exists,
            self._rule_intentional_zero_value,
            self._rule_invariant_already_enforced,
            self._rule_no_external_attacker_path,
            self._rule_test_file_exclusion,
        ]

        for rule_fn in rules:
            rule_id = rule_fn.__name__.replace("_rule_", "").upper()
            if not self._rule_enabled(rule_id):
                continue
            result = rule_fn(vuln, ctx)
            if result:
                reasons.append(result)

        # Compute aggregate fp_confidence
        if not reasons:
            fp_confidence = 0.0
        else:
            # Noisy-OR: each additional rule independently contributes evidence
            # P(FP) = 1 - product(1 - w_i)  — standard probabilistic combination
            weights = [r.fp_weight for r in reasons]
            fp_confidence = 1.0
            for w in weights:
                fp_confidence *= (1.0 - w)
            fp_confidence = min(1.0 - fp_confidence, 0.98)

        is_likely_fp = fp_confidence >= self.REVIEW_THRESHOLD

        # Determine recommended action
        if fp_confidence < self.SUBMIT_THRESHOLD:
            action = "SUBMIT"
        elif fp_confidence < self.REVIEW_THRESHOLD:
            action = "REVIEW"
        else:
            action = "SKIP"

        # Adjust severity if trust model or secondary condition flags hit
        original_severity = vuln.get("severity", "MEDIUM")
        adjusted_severity = self._adjust_severity(original_severity, reasons)

        # Build submit notes
        submit_notes = self._build_submit_notes(reasons, ctx)

        return FPVerdict(
            is_likely_fp=is_likely_fp,
            fp_confidence=round(fp_confidence, 3),
            fp_reasons=reasons,
            recommended_action=action,
            adjusted_severity=adjusted_severity,
            submit_notes=submit_notes,
        )

    # ─── RULE 1: TRUST MODEL ─────────────────────────────────────────────────

    def _rule_trust_model(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If the flagged function requires a privileged caller, exploitation
        requires a trusted actor to misbehave. Most programs reject this.

        Seen in: Doppler #333 (onlyApprovedMigrator)
        """
        privileged = [m for m in ctx.function_modifiers
                      if m in self.PRIVILEGED_MODIFIERS]
        if not privileged:
            return None

        return FPReason(
            rule_id="TRUST_MODEL",
            rule_name="Privileged Caller Required",
            explanation=(
                f"Function has modifier(s): {privileged}. "
                "Exploitation requires a trusted/privileged actor to call with "
                "malicious parameters. Most auditors classify this as "
                "admin-misconfiguration risk, not an external exploit. "
                "Severity is typically downgraded to LOW/INFORMATIONAL."
            ),
            fp_weight=0.75,
            evidence=f"Modifiers detected: {privileged}"
        )

    # ─── RULE 2: NON-STANDARD TOKEN ──────────────────────────────────────────

    def _rule_nonstandard_token(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If the finding only manifests with fee-on-transfer, rebasing, or ERC-777
        tokens and the protocol does NOT explicitly support them, expect rejection.

        Seen in: Doppler #226 (fee-on-transfer in TopUpDistributor)
        """
        desc = self._desc(vuln) + " " + vuln.get("fix_recommendation", "").lower()
        src = ctx.source_code.lower() + ctx.function_source.lower()

        # Detect which non-standard token type is relevant
        fot_hit = any(re.search(p, desc, re.I) or re.search(p, src, re.I)
                      for p in self.FOT_PATTERNS)
        rebase_hit = any(re.search(p, desc, re.I) for p in self.REBASE_PATTERNS)
        erc777_hit = any(re.search(p, desc, re.I) or re.search(p, src, re.I)
                         for p in self.ERC777_PATTERNS)

        triggered_types = []
        if fot_hit and not ctx.explicitly_supports_fot_tokens:
            triggered_types.append("fee-on-transfer")
        if rebase_hit and not ctx.explicitly_supports_rebasing:
            triggered_types.append("rebasing")
        if erc777_hit and not ctx.explicitly_supports_erc777:
            triggered_types.append("ERC-777")

        if not triggered_types:
            return None

        if ctx.token_whitelist_enforced:
            # If protocol enforces a token whitelist, non-standard tokens
            # can't even be added — even higher FP probability
            return FPReason(
                rule_id="NONSTANDARD_TOKEN",
                rule_name="Non-Standard Token + Whitelist",
                explanation=(
                    f"Finding involves {triggered_types} token(s) but protocol "
                    "enforces a token whitelist — non-standard tokens cannot be "
                    "added by untrusted parties. Near-certain rejection."
                ),
                fp_weight=0.90,
                evidence=f"Token types: {triggered_types}"
            )

        return FPReason(
            rule_id="NONSTANDARD_TOKEN",
            rule_name="Non-Standard Token Assumption",
            explanation=(
                f"Finding only manifests with {triggered_types} token(s). "
                "Standard ERC-20 tokens (which transfer exactly `amount`) "
                "are unaffected. Most programs consider non-standard token "
                "behaviour out of scope unless explicitly documented as supported."
            ),
            fp_weight=0.70,
            evidence=f"Non-standard token types: {triggered_types}"
        )

    # ─── RULE 3: SOLIDITY 0.8 IMPLICIT PROTECTION ───────────────────────────

    def _rule_sol08_implicit_protection(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        Solidity >= 0.8.0 reverts on arithmetic overflow/underflow automatically.
        Don't flag missing bounds checks on subtraction/addition in 0.8+ contracts.

        Seen in: Doppler #228 (getProtocolFees[token] -= amount already reverts)
        """
        vuln_type = vuln.get("vulnerability_type", "").upper()
        if vuln_type not in self.SOL08_ARITHMETIC_VULN_TYPES:
            # Also check description for arithmetic keywords
            desc = self._desc(vuln)
            arithmetic_keywords = [
                "overflow", "underflow", "missing bounds", "missing check",
                "no require", "no validation", "arithmetic",
                "-= amount", "+= amount"
            ]
            if not any(kw in desc for kw in arithmetic_keywords):
                return None

        # Check Solidity version
        version = ctx.solidity_version.strip().lstrip("^~>=")
        if not version:
            # Try to detect from source
            match = re.search(r"pragma solidity\s*[^;]*?(\d+\.\d+\.\d+)", ctx.source_code)
            if match:
                version = match.group(1)

        if not version:
            return None  # Can't determine — skip rule

        try:
            parts = [int(x) for x in version.split(".")[:2]]
            major, minor = parts[0], parts[1]
        except (ValueError, IndexError):
            return None

        if major > 0 or minor >= 8:
            return FPReason(
                rule_id="SOL08_IMPLICIT_PROTECTION",
                rule_name="Solidity 0.8+ Implicit Arithmetic Protection",
                explanation=(
                    f"Contract uses Solidity {version} (≥ 0.8.0). Arithmetic "
                    "operations revert automatically on overflow/underflow. "
                    "An explicit `require(amount <= balance)` before `balance -= amount` "
                    "provides no additional protection — the subtraction already reverts. "
                    "Triagers will reject this as 'implicit protection exists'."
                ),
                fp_weight=0.80,
                evidence=f"Solidity version: {version}"
            )
        return None

    # ─── RULE 4: REMAINDER HANDLED ELSEWHERE IN FUNCTION ────────────────────

    def _rule_remainder_handled(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        Precision loss / dust findings are invalid when the function captures
        the remainder at the end (last-share = total - sum(others) pattern).

        Seen in: Doppler #227 (remainder → beneficiaryFees at end of _onAfterSwap)
        """
        desc = self._desc(vuln)
        vuln_type = vuln.get("vulnerability_type", "").upper()

        precision_keywords = [
            "precision loss", "dust", "rounding", "muldiv", "round down",
            "permanently locked", "accumulate", "wei lost", "residual",
        ]
        if not any(kw in desc for kw in precision_keywords):
            if vuln_type not in ("PRECISION_LOSS", "DUST_ACCUMULATION"):
                return None

        # Check function source for remainder-capture pattern
        src = ctx.function_source
        if not src:
            src = ctx.source_code

        remainder_found = any(
            re.search(p, src, re.I) for p in self.REMAINDER_PATTERNS
        )

        if remainder_found:
            return FPReason(
                rule_id="REMAINDER_HANDLED",
                rule_name="Remainder Captured in Same Function",
                explanation=(
                    "The function source contains a remainder/residual capture pattern "
                    "(e.g. `lastShare = total - a - b - c` or assignment to beneficiaryFees). "
                    "Dust from integer division is not lost — it is allocated to the "
                    "last recipient. Triagers will reject this as 'dust captured by design'."
                ),
                fp_weight=0.85,
                evidence="Remainder pattern detected in function source"
            )

        return None

    # ─── RULE 5: REENTRANCY GUARD PRESENT ───────────────────────────────────

    def _rule_reentrancy_guard(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If the flagged function has nonReentrant modifier, reentrancy findings
        are almost certainly false positives.
        """
        vuln_type = vuln.get("vulnerability_type", "").upper()
        if "REENTRANCY" not in vuln_type:
            return None

        guards = [m for m in ctx.function_modifiers
                  if m in self.REENTRANCY_GUARD_MODIFIERS]

        # Also scan source for ReentrancyGuard inheritance
        src_lower = ctx.source_code.lower()
        has_guard_in_source = (
            "reentrancyguard" in src_lower or
            "nonreentrant" in src_lower or
            "_status" in src_lower  # OpenZeppelin ReentrancyGuard state var
        )

        if not guards and not has_guard_in_source:
            return None

        evidence = f"Modifiers: {guards}" if guards else "ReentrancyGuard detected in source"
        return FPReason(
            rule_id="REENTRANCY_GUARD",
            rule_name="Reentrancy Guard Detected",
            explanation=(
                f"Function is protected by {guards or 'ReentrancyGuard'}. "
                "The nonReentrant modifier prevents reentrant calls at the EVM level. "
                "Reentrancy attacks against guarded functions are not exploitable "
                "unless the guard itself is misconfigured (cross-function reentrancy)."
            ),
            fp_weight=0.85,
            evidence=evidence
        )

    # ─── RULE 6: SECONDARY CONDITION DEPENDENCY ─────────────────────────────

    def _rule_secondary_condition_dependency(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If a finding only triggers after a SEPARATE pre-existing bug,
        it is a cascading vulnerability — much lower severity, often rejected.

        Seen in: Doppler #228 ("requires a separate bug to create divergence")
        """
        desc = self._desc(vuln)
        rec = vuln.get("fix_recommendation", "").lower()

        dependency_keywords = [
            "if another bug", "requires a separate", "pre-existing",
            "only if", "combined with", "first requires",
            "introduced by", "another vulnerability", "secondary condition",
            "prerequisite", "divergence must first",
        ]

        # Also check if researcher listed a "Likelihood: Low" that mentions
        # needing a prior condition
        hit = any(kw in desc or kw in rec for kw in dependency_keywords)

        # Fallback: check if we have other related findings in the session
        # that would be the "first" bug
        if not hit and ctx.other_finding_titles:
            title = vuln.get("title", vuln.get("description", ""))[:80].lower()
            for other in ctx.other_finding_titles:
                if other.lower() != title and (
                    "fee" in other.lower() or "token" in other.lower()
                ):
                    hit = True
                    break

        if not hit:
            return None

        return FPReason(
            rule_id="SECONDARY_CONDITION",
            rule_name="Requires Pre-Existing Vulnerability",
            explanation=(
                "This finding only manifests after a separate independent bug "
                "creates the required precondition. Cascading vulnerabilities "
                "have significantly lower exploitability — triagers will either "
                "downgrade severity or reject unless the 'first' bug is also "
                "a confirmed finding in the same report."
            ),
            fp_weight=0.60,
            evidence="Secondary condition dependency detected in description"
        )

    # ─── RULE 7: VIEW FUNCTION ONLY ──────────────────────────────────────────

    def _rule_view_function_only(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        View/pure functions cannot modify state. Most 'vulnerabilities' in
        view functions are information disclosure at best — not fund loss.
        """
        if not ctx.flagged_function_is_view:
            return None

        # Exception: oracle manipulation via view function reading is valid
        vuln_type = vuln.get("vulnerability_type", "").upper()
        if "ORACLE" in vuln_type:
            return None

        return FPReason(
            rule_id="VIEW_FUNCTION_ONLY",
            rule_name="View Function — No State Change Possible",
            explanation=(
                "The flagged function is `view`/`pure`. It cannot modify contract "
                "state or transfer funds. Any vulnerability is limited to information "
                "disclosure. Fund-loss claims against view functions will be rejected."
            ),
            fp_weight=0.70,
            evidence=f"Function: {ctx.flagged_function_sig} (view)"
        )

    # ─── RULE 8: LEGITIMATE FLASH LOAN FEATURE ───────────────────────────────

    def _rule_legitimate_flash_loan_feature(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If the protocol explicitly offers flash loans as a feature, ChainEDR's
        FLASH_LOAN classifier may fire on normal protocol usage.
        """
        vuln_type = vuln.get("vulnerability_type", "").upper()
        if "FLASH_LOAN" not in vuln_type:
            return None

        if not ctx.has_flash_loan_feature:
            return None

        return FPReason(
            rule_id="LEGITIMATE_FLASH_LOAN",
            rule_name="Protocol Offers Flash Loans by Design",
            explanation=(
                "The protocol explicitly implements flash loan functionality. "
                "A FLASH_LOAN classification on a protocol that offers flash loans "
                "as a feature is likely flagging normal protocol usage. "
                "Confirm the finding shows exploitation *beyond* the intended "
                "flash loan use (e.g. price manipulation, reentrancy via callback)."
            ),
            fp_weight=0.55,
            evidence="ctx.has_flash_loan_feature = True"
        )

    # ─── RULE 9: PROXY / DELEGATECALL PATTERN ────────────────────────────────

    def _rule_proxy_delegatecall(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        Delegatecall in proxy contracts creates trace patterns that look like
        reentrancy or external calls but are normal proxy operation.
        """
        vuln_type = vuln.get("vulnerability_type", "").upper()
        if "REENTRANCY" not in vuln_type:
            return None

        src = ctx.source_code.lower() + ctx.function_source.lower()
        has_delegatecall = (
            "delegatecall" in src or
            "_delegate(" in src or
            "_fallback(" in src
        )
        has_proxy_context = (
            "proxy" in src or "implementation" in src or
            "eip1967" in src or "upgradeable" in src or
            ctx.has_upgrade_mechanism
        )
        is_proxy = has_delegatecall and has_proxy_context
        if not is_proxy:
            return None

        return FPReason(
            rule_id="PROXY_DELEGATECALL",
            rule_name="Proxy Pattern — Delegatecall Is Expected",
            explanation=(
                "Contract uses delegatecall as part of a proxy/upgradeable pattern. "
                "Delegatecall back into the proxy is normal proxy operation and "
                "appears as a 'recursive call' in execution traces. "
                "Confirm the reentrancy path goes to the TARGET contract, not "
                "the proxy itself executing expected delegatecall."
            ),
            fp_weight=0.60,
            evidence="Proxy/delegatecall pattern detected in source"
        )

    # ─── RULE 10: DUST BELOW ECONOMIC THRESHOLD ─────────────────────────────

    def _rule_dust_below_threshold(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        Precision loss findings where the maximum realistic loss is negligible
        (< 1000 wei per tx, or described as 'a few wei') are routinely rejected.
        """
        desc = self._desc(vuln)
        estimated_loss = vuln.get("estimated_loss_usd", None)

        precision_keywords = ["wei", "dust", "precision", "rounding", "muldiv"]
        has_precision_keyword = any(kw in desc for kw in precision_keywords)

        # Trigger on tiny reported loss even without precision keywords
        tiny_loss = estimated_loss is not None and estimated_loss < 100.0

        if not has_precision_keyword and not tiny_loss:
            return None

        # Look for explicit small-magnitude indicators
        small_magnitude = tiny_loss or any(phrase in desc for phrase in [
            "3 wei", "few wei", "1 wei", "2 wei", "negligible",
            "1000 wei", "dust per", "per transaction", "per call",
        ])

        # Or look for FullMath.mulDiv — classic dust pattern
        has_mulDiv = "muldiv" in desc or "muldiv" in ctx.function_source.lower()

        if not (small_magnitude or has_mulDiv):
            return None

        return FPReason(
            rule_id="DUST_BELOW_THRESHOLD",
            rule_name="Precision Loss Magnitude Is Negligible",
            explanation=(
                "The described precision loss is a few wei per transaction. "
                "At typical gas costs, the economic impact is far below the "
                "cost of remediation. Programs typically reject dust findings "
                "below ~1000 wei per transaction unless the contract processes "
                "extremely high volume AND the dust has no recovery mechanism."
            ),
            fp_weight=0.65,
            evidence="Small magnitude (wei-level) precision loss detected"
        )

    # ─── RULE 11: ADMIN RESCUE / RECOVERY EXISTS ─────────────────────────────

    def _rule_admin_rescue_exists(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If the finding claims funds are 'permanently locked' but the contract
        has a rescue/recover/sweep function, the 'permanent' claim is wrong.
        """
        desc = self._desc(vuln)
        permanent_keywords = [
            "permanently locked", "permanently stuck", "stuck in contract",
            "no recovery", "permanently inaccessible",
            "locked forever", "no rescue", "unrecoverable", "not recoverable",
        ]
        if not any(kw in desc for kw in permanent_keywords):
            return None

        # Check context flags
        has_rescue = ctx.has_rescue_function or ctx.has_pause_mechanism

        # Also scan source for rescue patterns
        if not has_rescue:
            src = ctx.source_code.lower()
            has_rescue = any(re.search(p, src, re.I) for p in self.RESCUE_PATTERNS)

        if not has_rescue:
            return None

        return FPReason(
            rule_id="ADMIN_RESCUE_EXISTS",
            rule_name="Recovery Mechanism Exists",
            explanation=(
                "The finding claims funds are 'permanently locked' but the contract "
                "contains a rescue/recover/sweep function or pause mechanism. "
                "Funds are NOT permanently locked — an admin can recover them. "
                "Remove 'permanent' from the claim and adjust impact accordingly."
            ),
            fp_weight=0.70,
            evidence="Rescue/recovery function detected in source"
        )

    # ─── RULE 12: INTENTIONAL ZERO / EDGE VALUE ──────────────────────────────

    def _rule_intentional_zero_value(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        Zero or boundary parameter values that are handled by design
        (e.g. DEAD_ADDRESS pattern for permanent locks with lockDuration=0).

        A zero value is only a bug if there's no legitimate use case for it
        AND no trusted gatekeeper controls the parameter.
        """
        param = ctx.flagged_parameter_name
        val = ctx.flagged_parameter_value
        src = ctx.source_code.lower()

        if val != 0 and val is not None:
            return None
        if not param:
            return None

        # If there's a DEAD_ADDRESS or address(0) special case in source
        # that explicitly handles the zero-duration scenario
        has_dead_address_pattern = (
            "dead_address" in src or
            "address(0)" in src or
            "0x000000000000000000000000000000000000dead" in src
        )

        # Is the zero value gated by privileged access?
        privileged = [m for m in ctx.function_modifiers
                      if m in self.PRIVILEGED_MODIFIERS]

        # Low z-score means the zero value is not anomalous — likely intentional
        value_z = vuln.get("z_scores", {}).get("value", 0)
        low_z_score = (value_z > 0) and (value_z < 3.0)

        if not has_dead_address_pattern and not privileged and not low_z_score:
            return None

        weight = 0.45 if not privileged else 0.60
        if low_z_score and not privileged:
            weight = 0.40  # slightly lower — z-score alone is weak evidence
        evidence_parts = []
        if has_dead_address_pattern:
            evidence_parts.append("DEAD_ADDRESS pattern in source")
        if privileged:
            evidence_parts.append(f"Privileged access: {privileged}")
        if low_z_score:
            evidence_parts.append(f"Low z-score ({value_z:.1f} < 3.0) — not anomalous")

        return FPReason(
            rule_id="INTENTIONAL_ZERO_VALUE",
            rule_name="Zero Value May Be Intentional by Design",
            explanation=(
                f"`{param} = {val}` may be an intentional design choice "
                "(e.g. permanent lock via DEAD_ADDRESS recipient, or admin-configured "
                "zero-duration for testing). Especially likely when the function "
                "is access-controlled. Confirm there is a genuine attack path "
                "beyond 'misconfiguration by trusted party'."
            ),
            fp_weight=weight,
            evidence=" | ".join(evidence_parts)
        )

    # ─── RULE 13: INVARIANT ALREADY ENFORCED ─────────────────────────────────

    def _rule_invariant_already_enforced(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        The vulnerability describes a missing check for something already enforced:
        1. By the EVM/compiler (Solidity 0.8 arithmetic, SafeMath)
        2. Explicitly in the source code via require() that matches invariant_violations
        """
        fix = vuln.get("fix_recommendation", "").lower()
        src = (ctx.function_source + " " + ctx.source_code).lower()
        safemath = "safemath" in src or "safeerc20" in src

        matched = []

        # ── Path 1: fix recommendation suggests a require already implicit ────
        already_protected_patterns = [
            (r"require\s*\(.*amount\s*<=\s*balance", "Solidity 0.8 underflow reverts first"),
            (r"require\s*\(.*!= address\(0\)", "OpenZeppelin Address.sol zero check"),
            (r"require\s*\(.*> 0", "Solidity 0.8 reverts on division by zero"),
        ]
        for pattern, reason in already_protected_patterns:
            if re.search(pattern, fix, re.I):
                version = ctx.solidity_version.strip().lstrip("^~>=")
                try:
                    parts = [int(x) for x in version.split(".")[:2]]
                    if parts[0] > 0 or parts[1] >= 8:
                        matched.append(reason)
                except (ValueError, IndexError):
                    pass
                if safemath:
                    matched.append("SafeMath already handles this")

        # ── Path 2: invariant_violations claim X must satisfy condition Y,
        #    but function_source already has require(X <op> Y) ───────────────
        for violation in vuln.get("invariant_violations", []):
            viol_lower = violation.lower()
            # Extract variable name (first word before "must")
            m = re.match(r"(\w+)\s+must\s+be\s+(>|>=|<|<=|!=|==)\s*(\S+)", viol_lower)
            if m:
                var, op, val = m.group(1), m.group(2), m.group(3)
                # Build a pattern to find require(var op val) in function source
                op_escaped = re.escape(op)
                val_escaped = re.escape(val.rstrip(";,)"))
                src_pattern = (
                    rf"require\s*\(\s*{re.escape(var)}\s*{op_escaped}\s*{val_escaped}"
                )
                if re.search(src_pattern, ctx.function_source, re.I):
                    matched.append(
                        f"require({var} {op} {val}) already in function source"
                    )

        if not matched:
            return None

        return FPReason(
            rule_id="INVARIANT_ALREADY_ENFORCED",
            rule_name="Invariant Already Enforced",
            explanation=(
                f"The invariant is already enforced in the source: {matched}. "
                "The finding is redundant — triagers will see the existing require()."
            ),
            fp_weight=0.75,
            evidence=f"Existing protections: {matched}"
        )

    # ─── RULE 14: NO EXTERNAL ATTACKER PATH ──────────────────────────────────

    def _rule_no_external_attacker_path(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        If ALL entry points to trigger the vulnerability are access-controlled
        AND there's no privilege escalation path, there's no external attacker.

        This is the strongest FP signal — combines trust model + no escalation.
        """
        # Need at least two privileged modifiers OR one + no permissionless path
        privileged = [m for m in ctx.function_modifiers
                      if m in self.PRIVILEGED_MODIFIERS]

        if not privileged:
            return None

        # Check if there's any permissionless function that feeds into this
        desc = self._desc(vuln)
        permissionless_entry = any(kw in desc for kw in [
            "permissionless", "anyone can", "any user", "external user",
            "no access control", "public function", "callable by anyone",
        ])

        if permissionless_entry:
            return None  # There IS an attacker path

        return FPReason(
            rule_id="NO_EXTERNAL_ATTACKER_PATH",
            rule_name="No Untrusted Actor Can Trigger This",
            explanation=(
                f"All identified entry points to this vulnerability require "
                f"privileged roles: {privileged}. With no privilege escalation "
                "path described, there is no external attacker. This is an "
                "admin risk / trust-the-admin scenario. Programs generally "
                "reject these as 'out of scope' or 'accepted risk'."
            ),
            fp_weight=0.80,
            evidence=f"Privileged modifiers: {privileged}, no permissionless path found"
        )

    # ─── RULE 15: TEST FILE EXCLUSION ────────────────────────────────────────

    # Indicators that identify test / mock / fixture files that should never
    # be reported as production vulnerabilities.
    TEST_FILE_INDICATORS = [
        "/test/", "/tests/", ".t.sol",
        "Mock", "mock", "Test", "test",
        "Fixture", "fixture", "Helper", "helper",
        "Stub", "stub", "Fake", "fake",
    ]

    def _rule_test_file_exclusion(self, vuln: Dict, ctx: AuditContext) -> Optional[FPReason]:
        """
        Findings in test / mock / fixture / helper files are virtually
        never valid production bugs. Intentional anti-patterns are common
        in test code (re-entrancy, no access control, etc.) and submitting
        them wastes the programme's triage bandwidth.

        Rule 15 — TEST_FILE_EXCLUSION
        """
        if not ctx.filepath:
            return None

        matched = [ind for ind in self.TEST_FILE_INDICATORS
                   if ind in ctx.filepath]
        if not matched:
            return None

        return FPReason(
            rule_id="TEST_FILE_EXCLUSION",
            rule_name="Finding Is in a Test / Mock File",
            explanation=(
                f"The contract file path '{ctx.filepath}' contains test/mock "
                f"indicator(s): {matched}. Vulnerabilities in test infrastructure "
                "are intentional and out of scope for bug bounty programmes."
            ),
            fp_weight=0.95,
            evidence=f"Path indicators matched: {matched}",
        )

    # ─── HELPERS ─────────────────────────────────────────────────────────────

    def _adjust_severity(self, original: str, reasons: List[FPReason]) -> str:
        """Downgrade severity based on FP rules that typically cause downgrades."""
        severity = original.upper()
        downgrade_triggers = {
            "TRUST_MODEL", "NO_EXTERNAL_ATTACKER_PATH", "SECONDARY_CONDITION",
            "VIEW_FUNCTION_ONLY", "NONSTANDARD_TOKEN",
        }
        triggered = {r.rule_id for r in reasons}

        if downgrade_triggers & triggered:
            idx = self.SEVERITY_ORDER.index(severity) if severity in self.SEVERITY_ORDER else 2
            # Downgrade by 1 step
            new_idx = min(idx + 1, len(self.SEVERITY_ORDER) - 1)
            return self.SEVERITY_ORDER[new_idx]

        return severity

    def _build_submit_notes(self, reasons: List[FPReason], ctx: AuditContext) -> str:
        """Build actionable notes for the researcher before submitting."""
        notes = []
        rule_ids = {r.rule_id for r in reasons}

        if "TRUST_MODEL" in rule_ids or "NO_EXTERNAL_ATTACKER_PATH" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Show a concrete attack path where an "
                "UNTRUSTED actor (not admin/owner) can trigger the vulnerability. "
                "If the only path is admin misconfiguration, reconsider submitting."
            )
        if "NONSTANDARD_TOKEN" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Confirm the protocol explicitly supports "
                "this token type. If not documented, add a note that the finding "
                "requires the admin to allowlist a non-standard token."
            )
        if "SOL08_IMPLICIT_PROTECTION" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Remove any fix that adds explicit require() "
                "for arithmetic bounds — Solidity 0.8 already does this. Focus "
                "the finding on the actual impact, not the missing check."
            )
        if "REMAINDER_HANDLED" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Trace the full function execution to the end. "
                "Confirm dust is NOT captured by a remainder assignment at the bottom."
            )
        if "SECONDARY_CONDITION" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: This finding requires a separate bug first. "
                "Either submit both together as a compound finding, or remove "
                "the secondary-condition dependency from the impact description."
            )
        if "ADMIN_RESCUE_EXISTS" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Remove 'permanently locked' from the impact. "
                "Replace with 'temporarily inaccessible until admin rescue'."
            )
        if "REENTRANCY_GUARD" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Verify the guard covers cross-function paths. "
                "nonReentrant blocks same-contract re-entry but NOT cross-contract "
                "read-only reentrancy (Curve-style). If your path goes view -> ETH "
                "callback -> state-write, the guard does not protect it."
            )
        if "VIEW_FUNCTION_ONLY" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Explain what state-changing downstream effect "
                "this view-function vulnerability enables. Without a fund-loss path, "
                "severity is at most INFORMATIONAL (information disclosure)."
            )
        if "PROXY_DELEGATECALL" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Confirm the reentrancy path targets the "
                "IMPLEMENTATION contract's state, not the proxy executing its own "
                "delegatecall (which is normal proxy operation)."
            )
        if "DUST_BELOW_THRESHOLD" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: Quantify dust accumulation over realistic volume. "
                "Show total loss at protocol scale (daily volume * dust per tx). "
                "Findings below $100 total impact are routinely rejected."
            )
        if "TEST_FILE_EXCLUSION" in rule_ids:
            notes.append(
                "BEFORE SUBMITTING: This finding is in a test/mock file — "
                "not valid for production bug bounty. Remove or retarget to "
                "the production contract that imports this pattern."
            )

        return " | ".join(notes)


# ─── CONVENIENCE FUNCTION ────────────────────────────────────────────────────

def check_finding(
    vuln_dict: Dict[str, Any],
    *,
    solidity_version: str = "",
    function_modifiers: List[str] = None,
    source_code: str = "",
    function_source: str = "",
    abi: List[Dict] = None,
    flagged_function_sig: str = "",
    flagged_function_is_view: bool = False,
    flagged_parameter_name: str = "",
    flagged_parameter_value: Any = None,
    explicitly_supports_fot_tokens: bool = False,
    explicitly_supports_rebasing: bool = False,
    explicitly_supports_erc777: bool = False,
    has_flash_loan_feature: bool = False,
    has_rescue_function: bool = False,
    token_whitelist_enforced: bool = False,
    other_finding_titles: List[str] = None,
    filepath: str = "",
    enabled_rules: List[str] = None,
    verbose: bool = True,
) -> FPVerdict:
    """
    One-call convenience wrapper for FalsePositiveFilter.

    Example:
        from chainedr.fp_filter import check_finding

        verdict = check_finding(
            vuln.to_dict(),
            solidity_version="0.8.19",
            function_modifiers=["onlyOwner"],
            source_code=source,
        )
        print(verdict.summary())
    """
    ctx = AuditContext(
        solidity_version=solidity_version,
        function_modifiers=function_modifiers or [],
        source_code=source_code,
        function_source=function_source,
        abi=abi or [],
        flagged_function_sig=flagged_function_sig,
        flagged_function_is_view=flagged_function_is_view,
        flagged_parameter_name=flagged_parameter_name,
        flagged_parameter_value=flagged_parameter_value,
        explicitly_supports_fot_tokens=explicitly_supports_fot_tokens,
        explicitly_supports_rebasing=explicitly_supports_rebasing,
        explicitly_supports_erc777=explicitly_supports_erc777,
        has_flash_loan_feature=has_flash_loan_feature,
        has_rescue_function=has_rescue_function,
        token_whitelist_enforced=token_whitelist_enforced,
        other_finding_titles=other_finding_titles or [],
        filepath=filepath,
    )
    verdict = FalsePositiveFilter(enabled_rules=enabled_rules).analyse(vuln_dict, ctx)
    if verbose:
        print(verdict.summary())
    return verdict
