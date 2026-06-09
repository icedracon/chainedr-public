"""
ChainEDR — OWASP Smart Contract Top 10: 2026 Mapping

Maps every ChainEDR check class to its OWASP SC Top 10 (2026) category.
Source: https://owasp.org/www-project-smart-contract-top-10/

Categories (2026 spec):
  SC01-Access-Control-Vulnerabilities
  SC02-Logic-Errors
  SC03-Reentrancy-Attacks
  SC04-Insufficient-Access-Control       (separate from SC01 — focuses on bridges/inter-chain)
  SC05-Oracle-Manipulation
  SC06-DoS-Denial-of-Service
  SC07-Integer-Overflow-and-Underflow
  SC08-Unchecked-External-Calls
  SC09-Front-running
  SC10-Denial-of-Service-via-Block-Stuffing

Plus emerging 2026 classes (not in original 10):
  EXT-Cross-Chain-Bridge
  EXT-ZK-Verifier
  EXT-MEV-Sandwich

Usage:
    from src.owasp_2026 import OWASP_MAPPING, owasp_for_check, coverage_report

    cat = owasp_for_check('safety_buffer_waterfall')
    # → 'SC02-Logic-Errors'

    report = coverage_report(list_of_findings)
    # → Markdown table per OWASP category
"""

from __future__ import annotations

from typing import Dict, List
from collections import Counter


# Map: ChainEDR check name → OWASP 2026 category
OWASP_MAPPING: Dict[str, str] = {
    # SC01 — Access Control
    'external_acl_delegation':       'SC01-Access-Control',
    'access_control':                'SC01-Access-Control',
    'param_ramp_sandwich':           'SC01-Access-Control',  # privileged param ramp
    'caller_is_new_to_protocol':     'SC01-Access-Control',

    # SC02 — Logic Errors
    'safety_buffer_waterfall':       'SC02-Logic-Errors',
    'rounding_direction':            'SC02-Logic-Errors',
    'rounding_asymmetry':            'SC02-Logic-Errors',
    'zero_min_internal':             'SC02-Logic-Errors',
    'root_precision':                'SC02-Logic-Errors',
    'vault_inflation':               'SC02-Logic-Errors',

    # SC03 — Reentrancy
    'cross_function_reentrancy':     'SC03-Reentrancy',
    'readonly_reentrancy':           'SC03-Reentrancy',
    'flash_loan_callback':           'SC03-Reentrancy',
    'reentrancy_eth':                'SC03-Reentrancy',
    'reentrancy_no_eth':             'SC03-Reentrancy',

    # SC04 — Insufficient Access Control (bridges/inter-chain)
    'bridge_address_validation_gap': 'SC04-Insufficient-Access-Control',
    'cross_contract_oracle_taint':   'SC04-Insufficient-Access-Control',
    'permit_surface':                'SC04-Insufficient-Access-Control',

    # SC05 — Oracle Manipulation
    'stale_oracle_data':             'SC05-Oracle-Manipulation',
    'missing_sequencer_check':       'SC05-Oracle-Manipulation',
    'oracle_manipulation':           'SC05-Oracle-Manipulation',
    'spot_price_oracle':             'SC05-Oracle-Manipulation',

    # SC06 — DoS
    'unbounded_loops':               'SC06-DoS',
    'unbounded_loop':                'SC06-DoS',
    'gas_griefing':                  'SC06-DoS',
    'dangerous_transfer':            'SC06-DoS',

    # SC07 — Integer Overflow/Underflow
    'silent_truncation':             'SC07-Integer-Overflow-Underflow',
    'integer_overflow':              'SC07-Integer-Overflow-Underflow',
    'silent_overflow':               'SC07-Integer-Overflow-Underflow',

    # SC08 — Unchecked External Calls
    'unchecked_calls':               'SC08-Unchecked-External-Calls',
    'unchecked_transfer':            'SC08-Unchecked-External-Calls',

    # SC09 — Front-running
    'sandwich_vulnerability':        'SC09-Front-running',
    'missing_slippage_protection':   'SC09-Front-running',
    'commit_reveal_missing':         'SC09-Front-running',

    # SC10 — Block-stuffing (rare; mostly liquidations)
    'liquidation_blockstuffing':     'SC10-Block-Stuffing',

    # Extended 2026 classes (not in original 10)
    'zk_verifier_misconfig':         'EXT-ZK-Verifier',
    'abi_decode_risks':              'EXT-ABI-Collision',
    'insecure_randomness':           'EXT-Weak-Randomness',
    'replay_protection':             'EXT-Signature-Replay',

    # EIP-7702 (Pectra, May 2025) — new attack surface, no other tool covers
    'AA7702-001':                    'SC01-Access-Control',   # tx.origin EOA bypass
    'AA7702-002':                    'SC01-Access-Control',   # isContract bypass
    'AA7702-003':                    'SC03-Reentrancy',       # callback reentrancy via EOA
    'AA7702-004':                    'EXT-EIP7702-Delegation', # cross-chain delegation replay
    'AA7702-005':                    'SC01-Access-Control',   # missing revocation
    'AA7702-006':                    'SC03-Reentrancy',       # delegatecall from delegation
}


# Severity tier per OWASP category (used for coverage scoring)
OWASP_BASE_SEVERITY: Dict[str, str] = {
    'SC01-Access-Control':              'CRITICAL',
    'SC02-Logic-Errors':                'HIGH',
    'SC03-Reentrancy':                  'CRITICAL',
    'SC04-Insufficient-Access-Control': 'HIGH',
    'SC05-Oracle-Manipulation':         'HIGH',
    'SC06-DoS':                         'MEDIUM',
    'SC07-Integer-Overflow-Underflow':  'HIGH',
    'SC08-Unchecked-External-Calls':    'MEDIUM',
    'SC09-Front-running':               'MEDIUM',
    'SC10-Block-Stuffing':              'LOW',
    'EXT-ZK-Verifier':                  'HIGH',
    'EXT-ABI-Collision':                'MEDIUM',
    'EXT-Weak-Randomness':              'HIGH',
    'EXT-EIP7702-Delegation':           'CRITICAL',
    'EXT-Signature-Replay':             'HIGH',
}


def owasp_for_check(check: str) -> str:
    """Return OWASP category for a ChainEDR check, or 'UNCLASSIFIED'."""
    return OWASP_MAPPING.get(check, 'UNCLASSIFIED')


def annotate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Add 'owasp_2026' key to each finding (in-place modification + return).
    """
    for f in findings:
        check = f.get('check', '')
        if 'owasp_2026' not in f:   # only add if detector didn't set it
            f['owasp_2026'] = owasp_for_check(check)
    return findings


def coverage_report(findings: List[Dict]) -> str:
    """Generate OWASP-grouped summary of findings."""
    annotated = annotate_findings(findings)
    by_cat: Dict[str, List[Dict]] = {}
    for f in annotated:
        cat = f.get('owasp_2026', 'UNCLASSIFIED')
        by_cat.setdefault(cat, []).append(f)

    lines = [
        f"{'─'*68}",
        "  OWASP Smart Contract Top 10 (2026) — Coverage Report",
        f"{'─'*68}",
    ]

    categories_order = [
        'SC01-Access-Control', 'SC02-Logic-Errors', 'SC03-Reentrancy',
        'SC04-Insufficient-Access-Control', 'SC05-Oracle-Manipulation',
        'SC06-DoS', 'SC07-Integer-Overflow-Underflow',
        'SC08-Unchecked-External-Calls', 'SC09-Front-running',
        'SC10-Block-Stuffing',
        'EXT-ZK-Verifier', 'EXT-ABI-Collision',
        'EXT-Weak-Randomness', 'EXT-Signature-Replay',
        'UNCLASSIFIED',
    ]
    for cat in categories_order:
        items = by_cat.get(cat, [])
        if not items and cat == 'UNCLASSIFIED':
            continue
        sev_count = Counter(f.get('severity', '?') for f in items)
        sev_str = " ".join(f"{k}={v}" for k, v in sev_count.most_common())
        marker = "  " if items else "  "
        status = (
            f"{len(items):3d} finding(s)" if items
            else "  no findings — category covered, none triggered"
        )
        lines.append(f"{marker}{cat:38s} {status:18s} {sev_str}")
    lines.append(f"{'─'*68}")
    return '\n'.join(lines)


def coverage_matrix() -> str:
    """Static matrix showing which checks map to each OWASP category."""
    by_cat: Dict[str, List[str]] = {}
    for check, cat in OWASP_MAPPING.items():
        by_cat.setdefault(cat, []).append(check)

    lines = [
        f"{'─'*68}",
        "  ChainEDR Detector → OWASP 2026 Coverage Matrix",
        f"{'─'*68}",
    ]
    for cat in sorted(by_cat.keys()):
        checks = sorted(by_cat[cat])
        lines.append(f"\n  {cat}:")
        for c in checks:
            lines.append(f"    - {c}")
    lines.append(f"\n{'─'*68}")
    return '\n'.join(lines)


def coverage_gaps() -> Dict[str, str]:
    """
    Return categories where we have NO detector mapped — these are gaps
    in our coverage of OWASP Top 10 2026.
    """
    all_cats = set(OWASP_BASE_SEVERITY.keys())
    covered = set(OWASP_MAPPING.values())
    gaps = all_cats - covered
    return {cat: OWASP_BASE_SEVERITY.get(cat, '?') for cat in gaps}
