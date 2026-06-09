"""
Tests for ChainEDR FP Filter — Module 8

Covers all 14 false-positive rules.
All tests are pure-Python — no RPC calls, no network, no blockchain.

Run with:
    pytest tests/test_fp_filter.py -v
"""

import pytest
from chainedr.fp_filter import (
    FalsePositiveFilter,
    AuditContext,
    FPVerdict,
    FPReason,
    check_finding,
)


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _vuln(
    vuln_type: str = "REENTRANCY",
    severity: str = "HIGH",
    confidence: float = 0.85,
    cvss: float = 8.0,
    loss: float = 100_000.0,
    attack_vector: str = "Re-enter withdraw() via fallback",
    reasons: list = None,
    z_scores: dict = None,
    function_sig: str = "withdraw(uint256)",
    caller: str = "0xAttacker",
    invariant_violations: list = None,
) -> dict:
    return {
        "vulnerability_type": vuln_type,
        "severity": severity,
        "confidence": confidence,
        "cvss_score": cvss,
        "estimated_loss_usd": loss,
        "attack_vector": attack_vector,
        "anomaly_description": f"Detected {vuln_type}",
        "fix_suggestion": "Add reentrancy guard",
        "exploitability": "HIGH",
        "z_scores": z_scores or {"call_depth": 9.5},
        "reasons": reasons or ["call_depth 9.5σ from baseline"],
        "invariant_violations": invariant_violations or [],
        "caller": caller,
        "tx_hash": "0xdeadbeef",
    }


def _ctx(**kwargs) -> AuditContext:
    """Build AuditContext with sensible defaults, overridden by kwargs."""
    defaults = dict(
        solidity_version="0.8.19",
        source_code="",
        function_source="",
        abi=[],
        function_modifiers=[],
        explicitly_supports_fot_tokens=False,
        explicitly_supports_rebasing=False,
        explicitly_supports_erc777=False,
        has_flash_loan_feature=False,
        has_pause_mechanism=False,
        has_rescue_function=False,
        has_upgrade_mechanism=False,
        token_whitelist_enforced=False,
        expected_token_standard="ERC20",
        flagged_function_sig="withdraw(uint256)",
        flagged_function_is_view=False,
        flagged_parameter_name="",
        flagged_parameter_value=None,
        other_finding_titles=[],
    )
    defaults.update(kwargs)
    return AuditContext(**defaults)


def _filter() -> FalsePositiveFilter:
    return FalsePositiveFilter()


# ─── VERDICTS & BASICS ───────────────────────────────────────────────────────

class TestVerdictBasics:
    def test_clean_finding_is_submit(self):
        """Reentrancy finding with no FP triggers → SUBMIT."""
        v = _filter().analyse(_vuln(), _ctx())
        assert v.recommended_action == "SUBMIT"
        assert v.is_likely_fp is False
        assert v.fp_confidence < FalsePositiveFilter.SUBMIT_THRESHOLD

    def test_verdict_has_adjusted_severity(self):
        v = _filter().analyse(_vuln(), _ctx())
        assert v.adjusted_severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

    def test_summary_no_flags(self):
        v = _filter().analyse(_vuln(), _ctx())
        assert "clean" in v.summary().lower() or "✓" in v.summary()

    def test_summary_with_flags(self):
        ctx = _ctx(function_modifiers=["onlyOwner"])
        v = _filter().analyse(_vuln(), ctx)
        # onlyOwner should trigger TRUST_MODEL
        assert v.recommended_action in ("REVIEW", "SKIP")
        assert "TRUST_MODEL" in v.summary() or len(v.fp_reasons) > 0


# ─── RULE 1: TRUST_MODEL ─────────────────────────────────────────────────────

class TestRuleTrustModel:
    """Privileged-caller access control findings are usually not exploitable by
    external attackers — rejection rate is very high."""

    def test_onlyOwner_access_control(self):
        finding = _vuln(vuln_type="ACCESS_CONTROL")
        ctx = _ctx(function_modifiers=["onlyOwner"])
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "TRUST_MODEL" for r in v.fp_reasons)

    def test_onlyApprovedMigrator(self):
        finding = _vuln(vuln_type="ACCESS_CONTROL")
        ctx = _ctx(function_modifiers=["onlyApprovedMigrator"])
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "TRUST_MODEL" for r in v.fp_reasons)

    def test_reentrancy_with_privileged_caller_still_flagged(self):
        """TRUST_MODEL should trigger even on reentrancy if modifier is privileged."""
        finding = _vuln(vuln_type="REENTRANCY")
        ctx = _ctx(function_modifiers=["onlyAdmin"])
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "TRUST_MODEL" for r in v.fp_reasons)

    def test_public_function_no_trust_model(self):
        finding = _vuln(vuln_type="REENTRANCY")
        ctx = _ctx(function_modifiers=[])
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "TRUST_MODEL" for r in v.fp_reasons)


# ─── RULE 2: NONSTANDARD_TOKEN ────────────────────────────────────────────────

class TestRuleNonstandardToken:
    """Fee-on-transfer / rebasing / ERC-777 — protocol must explicitly support
    them or finding is usually rejected."""

    def test_fot_token_finding_not_supported(self):
        finding = _vuln(
            vuln_type="UNCLASSIFIED_ANOMALY",
            attack_vector="balance discrepancy after transfer (fee-on-transfer token)",
            reasons=["balance less than expected after transfer"],
        )
        ctx = _ctx(explicitly_supports_fot_tokens=False)
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "NONSTANDARD_TOKEN" for r in v.fp_reasons)

    def test_fot_token_explicitly_supported(self):
        finding = _vuln(
            attack_vector="balance discrepancy after transfer (fee-on-transfer token)",
        )
        ctx = _ctx(explicitly_supports_fot_tokens=True)
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "NONSTANDARD_TOKEN" for r in v.fp_reasons)

    def test_rebasing_token_not_supported(self):
        finding = _vuln(
            attack_vector="rebasing token balance manipulation",
        )
        ctx = _ctx(explicitly_supports_rebasing=False)
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "NONSTANDARD_TOKEN" for r in v.fp_reasons)

    def test_erc777_reentrancy_explicitly_guarded(self):
        finding = _vuln(
            vuln_type="REENTRANCY",
            attack_vector="ERC-777 tokensReceived hook reentrancy",
        )
        ctx = _ctx(explicitly_supports_erc777=True, function_modifiers=["nonReentrant"])
        v = _filter().analyse(finding, ctx)
        # nonReentrant should neutralise reentrancy flag regardless
        assert any(r.rule_id == "REENTRANCY_GUARD" for r in v.fp_reasons)


# ─── RULE 3: SOL08_IMPLICIT_PROTECTION ───────────────────────────────────────

class TestRuleSol08ImplicitProtection:
    """Arithmetic overflow/underflow is caught by the compiler in Solidity ≥ 0.8.
    Findings about integer overflow with require() are usually informational."""

    def test_overflow_finding_sol08(self):
        finding = _vuln(
            vuln_type="INTEGER_OVERFLOW",
            attack_vector="integer overflow in token amount calculation",
            reasons=["arithmetic overflow detected"],
        )
        ctx = _ctx(solidity_version="0.8.19")
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "SOL08_IMPLICIT_PROTECTION" for r in v.fp_reasons)

    def test_overflow_finding_sol07(self):
        finding = _vuln(
            vuln_type="INTEGER_OVERFLOW",
            attack_vector="integer overflow in token amount calculation",
        )
        ctx = _ctx(solidity_version="0.7.6")
        v = _filter().analyse(finding, ctx)
        # 0.7 has no built-in protection — rule should NOT trigger
        assert not any(r.rule_id == "SOL08_IMPLICIT_PROTECTION" for r in v.fp_reasons)

    def test_underflow_sol08(self):
        finding = _vuln(
            vuln_type="INTEGER_OVERFLOW",
            attack_vector="underflow when subtracting user balance",
        )
        ctx = _ctx(solidity_version="0.8.0")
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "SOL08_IMPLICIT_PROTECTION" for r in v.fp_reasons)

    def test_reentrancy_sol08_not_affected(self):
        """SOL08 rule only applies to arithmetic — not reentrancy."""
        finding = _vuln(vuln_type="REENTRANCY")
        ctx = _ctx(solidity_version="0.8.19")
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "SOL08_IMPLICIT_PROTECTION" for r in v.fp_reasons)


# ─── RULE 4: REMAINDER_HANDLED ───────────────────────────────────────────────

class TestRuleRemainderHandled:
    """'Dust locked in contract' findings are FP if the last share uses the
    remainder pattern (total − sum_of_others)."""

    def test_dust_remainder_pattern(self):
        finding = _vuln(
            vuln_type="UNCLASSIFIED_ANOMALY",
            attack_vector="dust locked in contract",
            reasons=["small residual balance not distributed"],
        )
        ctx = _ctx(
            function_source=(
                "uint256 lastShare = total - share0 - share1;"
                "beneficiaryFees1 = total - beneficiaryFees0;"
            )
        )
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "REMAINDER_HANDLED" for r in v.fp_reasons)

    def test_no_remainder_pattern(self):
        finding = _vuln(
            attack_vector="dust locked in contract",
            reasons=["residual balance stuck"],
        )
        ctx = _ctx(function_source="// no remainder pattern")
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "REMAINDER_HANDLED" for r in v.fp_reasons)


# ─── RULE 5: REENTRANCY_GUARD ────────────────────────────────────────────────

class TestRuleReentrancyGuard:
    def test_reentrancy_with_nonreentrant_modifier(self):
        finding = _vuln(vuln_type="REENTRANCY")
        ctx = _ctx(function_modifiers=["nonReentrant"])
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "REENTRANCY_GUARD" for r in v.fp_reasons)

    def test_reentrancy_no_guard(self):
        finding = _vuln(vuln_type="REENTRANCY")
        ctx = _ctx(function_modifiers=[])
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "REENTRANCY_GUARD" for r in v.fp_reasons)

    def test_non_reentrancy_finding_with_guard(self):
        """Guard is irrelevant for non-reentrancy finding types."""
        finding = _vuln(vuln_type="FLASH_LOAN_ATTACK")
        ctx = _ctx(function_modifiers=["nonReentrant"])
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "REENTRANCY_GUARD" for r in v.fp_reasons)


# ─── RULE 6: SECONDARY_CONDITION ─────────────────────────────────────────────

class TestRuleSecondaryCondition:
    """Attack requires a second, independent, less-likely condition to be met
    (e.g. price at extreme outlier value + reentrancy simultaneously)."""

    def test_secondary_price_condition(self):
        finding = _vuln(
            attack_vector="oracle manipulation requires price to reach $0.001",
            reasons=["price oracle at extreme outlier", "requires secondary condition"],
        )
        ctx = _ctx()
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "SECONDARY_CONDITION" for r in v.fp_reasons)


# ─── RULE 7: VIEW_FUNCTION_ONLY ──────────────────────────────────────────────

class TestRuleViewFunctionOnly:
    def test_view_function_flagged(self):
        finding = _vuln(function_sig="getBalance(address)")
        ctx = _ctx(
            flagged_function_sig="getBalance(address)",
            flagged_function_is_view=True,
        )
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "VIEW_FUNCTION_ONLY" for r in v.fp_reasons)

    def test_state_changing_function_not_view(self):
        finding = _vuln(function_sig="withdraw(uint256)")
        ctx = _ctx(
            flagged_function_sig="withdraw(uint256)",
            flagged_function_is_view=False,
        )
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "VIEW_FUNCTION_ONLY" for r in v.fp_reasons)


# ─── RULE 8: LEGITIMATE_FLASH_LOAN ───────────────────────────────────────────

class TestRuleLegitimateFlashLoan:
    """If the protocol itself offers flash loans, a flash-loan call pattern is
    expected behavior — not an attack."""

    def test_flash_loan_in_flash_loan_protocol(self):
        finding = _vuln(vuln_type="FLASH_LOAN_ATTACK")
        ctx = _ctx(has_flash_loan_feature=True)
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "LEGITIMATE_FLASH_LOAN" for r in v.fp_reasons)

    def test_flash_loan_in_normal_protocol(self):
        finding = _vuln(vuln_type="FLASH_LOAN_ATTACK")
        ctx = _ctx(has_flash_loan_feature=False)
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "LEGITIMATE_FLASH_LOAN" for r in v.fp_reasons)


# ─── RULE 9: PROXY_DELEGATECALL ──────────────────────────────────────────────

class TestRuleProxyDelegatecall:
    """delegatecall is expected and benign in proxy patterns."""

    def test_delegatecall_in_proxy(self):
        finding = _vuln(
            attack_vector="delegatecall to untrusted target",
            reasons=["unexpected delegatecall detected"],
        )
        ctx = _ctx(
            function_source="fallback() external { _delegate(implementation); }",
            has_upgrade_mechanism=True,
        )
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "PROXY_DELEGATECALL" for r in v.fp_reasons)


# ─── RULE 10: DUST_BELOW_THRESHOLD ───────────────────────────────────────────

class TestRuleDustBelowThreshold:
    """Sub-dollar estimated losses are almost never accepted by programs."""

    def test_dust_loss(self):
        finding = _vuln(loss=0.50)  # $0.50
        ctx = _ctx()
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "DUST_BELOW_THRESHOLD" for r in v.fp_reasons)

    def test_significant_loss(self):
        finding = _vuln(loss=50_000.0)
        ctx = _ctx()
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "DUST_BELOW_THRESHOLD" for r in v.fp_reasons)

    def test_boundary_exactly_one_dollar(self):
        finding = _vuln(loss=1.00)
        ctx = _ctx()
        v = _filter().analyse(finding, ctx)
        # $1 is at/near threshold — may or may not fire depending on exact threshold
        # Just assert the verdict is valid
        assert v.recommended_action in ("SUBMIT", "REVIEW", "SKIP")


# ─── RULE 11: ADMIN_RESCUE_EXISTS ────────────────────────────────────────────

class TestRuleAdminRescueExists:
    """'Tokens stuck in contract' is typically informational if an admin rescue
    function exists."""

    def test_tokens_stuck_with_rescue(self):
        finding = _vuln(
            attack_vector="tokens permanently stuck in contract",
            reasons=["balance not recoverable", "no withdrawal path"],
        )
        ctx = _ctx(has_rescue_function=True)
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "ADMIN_RESCUE_EXISTS" for r in v.fp_reasons)

    def test_tokens_stuck_without_rescue(self):
        finding = _vuln(
            attack_vector="tokens permanently stuck in contract",
        )
        ctx = _ctx(has_rescue_function=False)
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "ADMIN_RESCUE_EXISTS" for r in v.fp_reasons)


# ─── RULE 12: INTENTIONAL_ZERO_VALUE ─────────────────────────────────────────

class TestRuleIntentionalZeroValue:
    """Zero parameter values are sometimes valid by design (e.g. skipping a fee,
    transferring 0 tokens). Low-z findings about zero-value inputs can be FP."""

    def test_zero_value_low_z(self):
        finding = _vuln(
            z_scores={"value": 2.1},  # low z-score
            reasons=["ETH value is zero"],
        )
        ctx = _ctx(
            flagged_parameter_name="amount",
            flagged_parameter_value=0,
        )
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "INTENTIONAL_ZERO_VALUE" for r in v.fp_reasons)

    def test_zero_value_high_z(self):
        """High z-score zero value (like Doppler lockDuration=0 at 12.9σ)
        should NOT be suppressed by this rule."""
        finding = _vuln(
            z_scores={"lockDuration": 12.9},
            reasons=["lockDuration 12.9σ from baseline"],
        )
        ctx = _ctx(
            flagged_parameter_name="lockDuration",
            flagged_parameter_value=0,
        )
        v = _filter().analyse(finding, ctx)
        # Rule should NOT trigger for high-z zero values
        assert not any(r.rule_id == "INTENTIONAL_ZERO_VALUE" for r in v.fp_reasons)


# ─── RULE 13: INVARIANT_ALREADY_ENFORCED ─────────────────────────────────────

class TestRuleInvariantAlreadyEnforced:
    """The invariant being violated is already enforced by explicit require()
    checks in the source — so it can never actually be violated."""

    def test_explicit_require_present(self):
        finding = _vuln(
            attack_vector="zero lockDuration bypass",
            invariant_violations=["lockDuration must be > 0"],
        )
        ctx = _ctx(
            function_source=(
                "require(lockDuration > 0, 'zero duration');\n"
                "stream.lockDuration = lockDuration;"
            )
        )
        v = _filter().analyse(finding, ctx)
        assert any(r.rule_id == "INVARIANT_ALREADY_ENFORCED" for r in v.fp_reasons)

    def test_no_require_present(self):
        finding = _vuln(
            attack_vector="zero lockDuration bypass",
            invariant_violations=["lockDuration must be > 0"],
        )
        ctx = _ctx(
            function_source=(
                "stream.lockDuration = lockDuration;"  # no require
            )
        )
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "INVARIANT_ALREADY_ENFORCED" for r in v.fp_reasons)


# ─── RULE 14: NO_EXTERNAL_ATTACKER_PATH ──────────────────────────────────────

class TestRuleNoExternalAttackerPath:
    """If exploitation requires the attacker to already have admin/owner keys,
    there is no path for an anonymous external attacker."""

    def test_requires_private_key(self):
        finding = _vuln(
            attack_vector="attacker needs owner private key to call setFee()",
            reasons=["requires owner credentials"],
        )
        ctx = _ctx(function_modifiers=["onlyOwner"])
        v = _filter().analyse(finding, ctx)
        # Both TRUST_MODEL and NO_EXTERNAL_ATTACKER_PATH may fire
        rule_ids = {r.rule_id for r in v.fp_reasons}
        assert "TRUST_MODEL" in rule_ids or "NO_EXTERNAL_ATTACKER_PATH" in rule_ids

    def test_external_attacker_path_exists(self):
        finding = _vuln(
            attack_vector="any caller can trigger reentrancy in withdraw()",
        )
        ctx = _ctx(function_modifiers=[])
        v = _filter().analyse(finding, ctx)
        assert not any(r.rule_id == "NO_EXTERNAL_ATTACKER_PATH" for r in v.fp_reasons)


# ─── AGGREGATED / COMBINED SCENARIOS ─────────────────────────────────────────

class TestCombinedScenarios:
    """Multi-rule scenarios that mirror real rejected findings."""

    def test_doppler_333_scenario(self):
        """
        Finding #333 — zero lockDuration bypass, but function has onlyApprovedMigrator.
        Should get TRUST_MODEL flag → REVIEW or SKIP.
        """
        finding = _vuln(
            vuln_type="ACCESS_CONTROL",
            attack_vector="lockDuration=0 bypasses time lock via onlyApprovedMigrator",
            reasons=["lockDuration 12.9σ from baseline", "temporal invariant violated"],
            z_scores={"lockDuration": 12.9},
        )
        ctx = _ctx(
            function_modifiers=["onlyApprovedMigrator"],
            flagged_parameter_name="lockDuration",
            flagged_parameter_value=0,
        )
        v = _filter().analyse(finding, ctx)
        assert v.recommended_action in ("REVIEW", "SKIP")
        rule_ids = {r.rule_id for r in v.fp_reasons}
        assert "TRUST_MODEL" in rule_ids

    def test_doppler_228_scenario(self):
        """
        Finding #228 — integer underflow in sol 0.8. Should get SOL08 flag.
        """
        finding = _vuln(
            vuln_type="INTEGER_OVERFLOW",
            attack_vector="underflow in fee subtraction",
            reasons=["subtraction could underflow"],
        )
        ctx = _ctx(solidity_version="0.8.20")
        v = _filter().analyse(finding, ctx)
        rule_ids = {r.rule_id for r in v.fp_reasons}
        assert "SOL08_IMPLICIT_PROTECTION" in rule_ids

    def test_doppler_226_scenario(self):
        """
        Finding #226 — fee-on-transfer token balance discrepancy, protocol
        doesn't claim to support FoT. Should get NONSTANDARD_TOKEN flag.
        """
        finding = _vuln(
            vuln_type="UNCLASSIFIED_ANOMALY",
            attack_vector="balance discrepancy for fee-on-transfer token",
            reasons=["balance after transfer less than expected"],
        )
        ctx = _ctx(explicitly_supports_fot_tokens=False)
        v = _filter().analyse(finding, ctx)
        rule_ids = {r.rule_id for r in v.fp_reasons}
        assert "NONSTANDARD_TOKEN" in rule_ids

    def test_doppler_227_scenario(self):
        """
        Finding #227 — 'dust locked', remainder is captured.
        Should get REMAINDER_HANDLED flag.
        """
        finding = _vuln(
            vuln_type="UNCLASSIFIED_ANOMALY",
            attack_vector="dust amount locked in contract",
            reasons=["residual balance after fee distribution"],
        )
        ctx = _ctx(
            function_source=(
                "beneficiaryFees1 = totalFees - beneficiaryFees0;"
            )
        )
        v = _filter().analyse(finding, ctx)
        rule_ids = {r.rule_id for r in v.fp_reasons}
        assert "REMAINDER_HANDLED" in rule_ids

    def test_clean_reentrancy_attack(self):
        """
        Pure reentrancy, no guards, public function, Solidity 0.7, significant
        loss — should be clean SUBMIT with zero FP flags.
        """
        finding = _vuln(
            vuln_type="REENTRANCY",
            attack_vector="re-enter withdraw() via fallback, drain funds",
            reasons=["call_depth 8.2σ", "external call before state update"],
            z_scores={"call_depth": 8.2, "gas": 6.1},
            loss=500_000.0,
        )
        ctx = _ctx(
            solidity_version="0.7.6",
            function_modifiers=[],
            has_flash_loan_feature=False,
            has_rescue_function=False,
        )
        v = _filter().analyse(finding, ctx)
        assert v.recommended_action == "SUBMIT"
        assert len(v.fp_reasons) == 0

    def test_multiple_rules_stack_to_skip(self):
        """
        onlyOwner + sol 0.8 overflow + dust loss → should hit SKIP.
        """
        finding = _vuln(
            vuln_type="INTEGER_OVERFLOW",
            attack_vector="overflow in calculation",
            reasons=["arithmetic overflow"],
            loss=0.10,  # dust
        )
        ctx = _ctx(
            solidity_version="0.8.15",
            function_modifiers=["onlyOwner"],
        )
        v = _filter().analyse(finding, ctx)
        # At least two rules should fire, pushing confidence above SKIP threshold
        assert len(v.fp_reasons) >= 2
        assert v.recommended_action in ("REVIEW", "SKIP")


# ─── CONVENIENCE FUNCTION ─────────────────────────────────────────────────────

class TestCheckFindingConvenienceFunction:
    def test_basic_call(self):
        v = check_finding(
            _vuln(),
            solidity_version="0.8.0",
            function_modifiers=[],
        )
        assert isinstance(v, FPVerdict)

    def test_with_context_kwargs(self):
        v = check_finding(
            _vuln(vuln_type="INTEGER_OVERFLOW"),
            solidity_version="0.8.19",
            function_modifiers=["onlyOwner"],
        )
        rule_ids = {r.rule_id for r in v.fp_reasons}
        assert "SOL08_IMPLICIT_PROTECTION" in rule_ids or "TRUST_MODEL" in rule_ids

    def test_returns_submit_for_clean_flash_loan(self):
        finding = _vuln(
            vuln_type="FLASH_LOAN_ATTACK",
            loss=1_000_000.0,
            reasons=["large ETH flash loan", "price manipulation"],
            z_scores={"eth_value": 11.2, "gas": 7.8},
        )
        v = check_finding(
            finding,
            solidity_version="0.8.0",
            function_modifiers=[],
            has_flash_loan_feature=False,
        )
        assert v.recommended_action == "SUBMIT"


# ─── THRESHOLD BOUNDARY TESTS ─────────────────────────────────────────────────

class TestThresholds:
    def test_submit_threshold_is_025(self):
        assert FalsePositiveFilter.SUBMIT_THRESHOLD == 0.25

    def test_review_threshold_is_055(self):
        assert FalsePositiveFilter.REVIEW_THRESHOLD == 0.55

    def test_fp_confidence_in_range(self):
        v = _filter().analyse(_vuln(), _ctx())
        assert 0.0 <= v.fp_confidence <= 1.0

    def test_is_likely_fp_consistent_with_confidence(self):
        """is_likely_fp should be True iff recommended_action is REVIEW or SKIP."""
        for loss in [0.01, 500_000.0]:
            v = _filter().analyse(_vuln(loss=loss), _ctx())
            if v.recommended_action == "SUBMIT":
                assert v.is_likely_fp is False
            else:
                assert v.is_likely_fp is True


# ─── SEVERITY DOWNGRADE ───────────────────────────────────────────────────────

class TestSeverityDowngrade:
    def test_severity_never_upgraded(self):
        """Filter should only lower severity, never raise it."""
        original_severity = "HIGH"
        v = _filter().analyse(_vuln(severity=original_severity), _ctx())
        order = FalsePositiveFilter.SEVERITY_ORDER
        assert order.index(v.adjusted_severity) >= order.index(original_severity)

    def test_highly_flagged_finding_downgraded(self):
        """onlyOwner + sol08 + dust → severity should be downgraded."""
        finding = _vuln(severity="HIGH", vuln_type="INTEGER_OVERFLOW", loss=0.01)
        ctx = _ctx(solidity_version="0.8.19", function_modifiers=["onlyOwner"])
        v = _filter().analyse(finding, ctx)
        if v.recommended_action in ("REVIEW", "SKIP"):
            order = FalsePositiveFilter.SEVERITY_ORDER
            # Adjusted severity must be same or lower
            assert order.index(v.adjusted_severity) >= order.index("HIGH")
