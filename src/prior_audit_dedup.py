"""
ChainEDR — Prior Audit Deduplication

Before submitting a finding, check whether it was already reported in a
public audit. Submitting known issues loses credibility with judges.

Architecture:
  PriorAuditDB — fingerprint database of known public findings
  PriorAuditFilter.filter() — mark findings already seen in public audits

Fingerprint: (check_class, affected_function_name_pattern)
  Fuzzy match: finding fires on function "applyLosses" + check "safety_buffer_waterfall"
  → matches prior entry for "InfiniFi YieldSharing waterfall" if known

Public audit sources indexed here:
  - Spearbit / Cantina reports
  - Code4rena (wardens)
  - Sherlock contests
  - ChainSecurity / Trail of Bits (where public)

Usage:
    from src.prior_audit_dedup import PriorAuditFilter

    dedup = PriorAuditFilter()
    findings = dedup.filter(findings)
    # findings now have 'prior_audit' key if previously reported
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ── Known prior finding fingerprints ────────────────────────────────────────
# Format: {
#   'id':       unique identifier
#   'check':    ChainEDR check name (or None for any)
#   'fn_pat':   regex pattern matching affected function name
#   'protocol': protocol name
#   'report':   public report reference
#   'severity': original severity in that report
#   'desc':     brief description
# }
#
# Sources: Spearbit/Cantina public reports, Code4rena, Sherlock
# Last updated: 2026-05

PRIOR_FINDINGS: List[dict] = [
    # ── ERC4626 inflation / donation attacks ────────────────────────────────
    {
        'id': 'P001',
        'check': 'vault_inflation',
        'fn_pat': r'deposit|mint|totalAssets|previewDeposit',
        'protocol': 'Generic ERC4626',
        'report': 'EIP-4626: first depositor attack (widely documented)',
        'severity': 'HIGH',
        'desc': 'First depositor can inflate share price via donation attack',
    },
    {
        'id': 'P002',
        'check': 'vault_inflation',
        'fn_pat': r'deposit|mint',
        'protocol': 'Sherlock contest (generic ERC4626)',
        'report': 'Sherlock: ERC4626 inflation vulnerability (multiple reports)',
        'severity': 'HIGH',
        'desc': 'Vault share price manipulation via single-wei deposit + donation',
    },

    # ── Stale oracle / Chainlink ────────────────────────────────────────────
    {
        'id': 'P003',
        'check': 'stale_oracle_data',
        'fn_pat': r'getPrice|price|latestAnswer|latestRoundData',
        'protocol': 'Generic Chainlink consumer',
        'report': 'Code4rena: missing updatedAt staleness check (100+ reports)',
        'severity': 'MEDIUM',
        'desc': 'Chainlink latestRoundData() without staleness validation',
    },
    {
        'id': 'P004',
        'check': 'missing_sequencer_check',
        'fn_pat': r'getPrice|price|oracle',
        'protocol': 'L2 Chainlink consumers',
        'report': 'Code4rena/Sherlock: missing L2 sequencer uptime check',
        'severity': 'HIGH',
        'desc': 'Chainlink oracle used on L2 without sequencer uptime check',
    },

    # ── Reentrancy ──────────────────────────────────────────────────────────
    {
        'id': 'P005',
        'check': 'readonly_reentrancy',
        'fn_pat': r'getVirtualPrice|get_virtual_price|price|totalAssets',
        'protocol': 'Curve-based protocols',
        'report': 'Curve/Euler: read-only reentrancy via get_virtual_price()',
        'severity': 'HIGH',
        'desc': 'Read-only reentrancy: view call returns stale state during re-entry',
    },
    {
        'id': 'P006',
        'check': 'cross_function_reentrancy',
        'fn_pat': r'withdraw|redeem|burn|transfer',
        'protocol': 'Generic ERC20/ERC777',
        'report': 'DAO hack class (widely documented)',
        'severity': 'CRITICAL',
        'desc': 'Cross-function reentrancy via external call before state update',
    },

    # ── Permit / EIP-2612 ───────────────────────────────────────────────────
    {
        'id': 'P007',
        'check': 'permit_surface',
        'fn_pat': r'permit|depositWithPermit|supplyWithPermit',
        'protocol': 'Generic EIP-2612 consumers',
        'report': 'Code4rena: permit front-run (griefing, multiple reports)',
        'severity': 'LOW',
        'desc': 'Permit can be front-run with same signature causing DoS',
    },

    # ── Sandwich / slippage ─────────────────────────────────────────────────
    {
        'id': 'P008',
        'check': 'sandwich_vulnerability',
        'fn_pat': r'swap|addLiquidity|removeLiquidity',
        'protocol': 'Uniswap/Sushiswap consumers',
        'report': 'Code4rena: zero slippage / slot0 sandwich (common)',
        'severity': 'HIGH',
        'desc': 'Swap with zero/no minimum output protection',
    },

    # ── Dangerous transfer ──────────────────────────────────────────────────
    {
        'id': 'P009',
        'check': 'dangerous_transfer',
        'fn_pat': r'transfer|withdraw|claim',
        'protocol': 'Generic ETH sender',
        'report': 'OpenZeppelin: .transfer() gas limit issues (well-known)',
        'severity': 'MEDIUM',
        'desc': '.transfer()/.send() fail on contracts with >2300 gas fallback',
    },

    # ── Protocol-specific: InfiniFi ─────────────────────────────────────────
    {
        'id': 'P-INF-001',
        'check': 'safety_buffer_waterfall',
        'fn_pat': r'_handleNegativeYield|handleNegativeYield|applyLosses',
        'protocol': 'InfiniFi',
        'report': 'ChainEDR audit 2026-05 (original finding — NOT prior)',
        'severity': 'HIGH',
        'desc': 'Safety buffer not consumed before propagating loss downstream',
        'is_original': True,  # We found this — not a prior
    },

    # ── Access control patterns ─────────────────────────────────────────────
    {
        'id': 'P010',
        'check': 'external_acl_delegation',
        'fn_pat': r'transferOwnership|setOwner|setAdmin|upgradeTo',
        'protocol': 'Generic upgradeable/ownable',
        'report': 'SWC-106: unprotected self-destruct / SWC-105: unprotected upgrades',
        'severity': 'CRITICAL',
        'desc': 'Unprotected critical function callable by any address',
    },

    # ── Integer issues ──────────────────────────────────────────────────────
    {
        'id': 'P011',
        'check': 'silent_truncation',
        'fn_pat': r'.*',   # any function
        'protocol': 'Generic',
        'report': 'SWC-101: integer overflow/underflow (pre-0.8 or explicit unchecked)',
        'severity': 'HIGH',
        'desc': 'Integer truncation without range check',
    },

    # ── Flash loan ──────────────────────────────────────────────────────────
    {
        'id': 'P012',
        'check': 'flash_loan_callback',
        'fn_pat': r'executeOperation|onFlashLoan|uniswapV2Call|pancakeCall',
        'protocol': 'Flash loan callback consumers',
        'report': 'Code4rena: unprotected flash loan callback (common)',
        'severity': 'HIGH',
        'desc': 'Flash loan callback lacks caller/initiator check',
    },
]


# ── Deduplication logic ──────────────────────────────────────────────────────

@dataclass
class PriorMatch:
    prior_id: str
    protocol: str
    report: str
    original_severity: str
    match_reason: str
    is_original_finding: bool = False


def _match_finding(finding: dict, prior: dict) -> Optional[PriorMatch]:
    """Check if a finding matches a prior audit entry."""
    check = finding.get('check', '')
    fn_name = finding.get('function', '') or finding.get('function_sig', '')

    # Check match: exact or None (matches any)
    if prior.get('check') and prior['check'] != check:
        return None

    # Function pattern match
    fn_pat = prior.get('fn_pat', '')
    if fn_pat and fn_name and not re.search(fn_pat, fn_name, re.I):
        return None

    return PriorMatch(
        prior_id=prior['id'],
        protocol=prior.get('protocol', ''),
        report=prior.get('report', ''),
        original_severity=prior.get('severity', ''),
        match_reason=f"check={check}, function matches /{fn_pat}/",
        is_original_finding=prior.get('is_original', False),
    )


class PriorAuditFilter:
    """
    Check ChainEDR findings against the prior audit database.

    Findings that match a known prior:
      - Get a 'prior_audit' annotation explaining the match
      - Severity is NOT changed (you may still submit if it's worse in this protocol)
      - 'is_novel' flag set to False unless prior is marked 'is_original'

    Findings NOT in prior:
      - Get 'is_novel': True
      - No annotation

    Usage:
        dedup = PriorAuditFilter()
        annotated = dedup.filter(findings)
    """

    def __init__(self, extra_priors: List[dict] = None):
        self._priors = PRIOR_FINDINGS + (extra_priors or [])

    def filter(self, findings: List[dict]) -> List[dict]:
        """
        Annotate findings with prior audit information.
        Returns all findings (does NOT suppress — that's the caller's decision).
        """
        result = []
        for f in findings:
            annotated = dict(f)
            matches = self._check_finding(f)
            if matches:
                best = matches[0]  # highest-priority match
                annotated['prior_audit'] = {
                    'prior_id': best.prior_id,
                    'protocol': best.protocol,
                    'report': best.report,
                    'original_severity': best.original_severity,
                    'match_reason': best.match_reason,
                }
                annotated['is_novel'] = best.is_original_finding
                if not best.is_original_finding:
                    # Add context to description
                    annotated['submission_note'] = (
                        f"PRIOR ART [{best.prior_id}]: This class of issue was "
                        f"previously reported in {best.protocol} "
                        f"({best.original_severity}). Ensure your report focuses "
                        f"on the protocol-specific impact, not just pattern presence."
                    )
            else:
                annotated['is_novel'] = True
            result.append(annotated)
        return result

    def novel_only(self, findings: List[dict]) -> List[dict]:
        """Return only findings with no prior audit match."""
        return [f for f in self.filter(findings) if f.get('is_novel', True)]

    def _check_finding(self, finding: dict) -> List[PriorMatch]:
        matches = []
        for prior in self._priors:
            m = _match_finding(finding, prior)
            if m:
                matches.append(m)
        return matches

    def summary(self, findings: List[dict]) -> str:
        """Print prior audit annotation summary."""
        annotated = self.filter(findings)
        novel = [f for f in annotated if f.get('is_novel', True)]
        prior_matched = [f for f in annotated if not f.get('is_novel', True)]

        lines = [
            f"{'─'*60}",
            f"  Prior Audit Deduplication",
            f"{'─'*60}",
            f"  Total findings:   {len(annotated)}",
            f"  Novel (submit):   {len(novel)}",
            f"  Prior-matched:    {len(prior_matched)} (known issue class)",
        ]
        if prior_matched:
            lines.append("\n  Prior-matched findings (not novel):")
            for f in prior_matched:
                pa = f.get('prior_audit', {})
                lines.append(
                    f"    [{f.get('severity','?')}] {f.get('check','?')} "
                    f"-> {pa.get('prior_id','')} ({pa.get('protocol','')})"
                )
        lines.append(f"{'─'*60}")
        return '\n'.join(lines)
