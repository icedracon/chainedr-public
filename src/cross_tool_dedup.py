"""
ChainEDR — Cross-Tool Finding Deduplication

When Slither + ChainEDR + Wake all detect the same bug, we should report
it ONCE with `detected_by=[slither, chainedr, wake]` — not three times
in the output.

Multi-tool consensus is also a CONFIDENCE BOOST signal: a finding caught
by 3 tools is much more likely real than one caught by a single tool.

Canonical key for dedup:
    (canonical_category, file_basename, function_name)

Where canonical_category maps Slither's `reentrancy-eth`, Mythril's
`SWC-107`, ChainEDR's `cross_function_reentrancy` → all to `REENTRANCY`.

Usage:
    from src.cross_tool_dedup import deduplicate_across_tools

    merged = deduplicate_across_tools(findings)
    # Each finding now has 'detected_by': List[str] and
    # consensus_confidence boost based on tool agreement.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


# ── Tool-to-canonical category mapping ────────────────────────────────────────
# Each tool uses its own taxonomy; normalize to a small canonical set.

CANONICAL_CATEGORIES = {
    'REENTRANCY',          # cross-function + read-only + ETH
    'ACCESS_CONTROL',      # missing/weak ACL
    'ORACLE',              # stale/manipulated price feeds
    'INTEGER',             # overflow/underflow/truncation
    'EXTERNAL_CALL',       # unchecked/dangerous low-level
    'DELEGATECALL',        # controlled/unprotected delegatecall
    'RANDOMNESS',          # weak prng / block.timestamp
    'DOS',                 # unbounded loops, gas griefing
    'FRONTRUNNING',        # sandwich, slippage missing
    'LOGIC',               # waterfall, rounding, vault inflation
    'SIGNATURE',           # replay, malleability, missing nonce
    'INITIALIZATION',      # uninitialized proxy, frontrunnable init
    'BRIDGE',              # cross-chain validation gap
    'ZK',                  # verifier misconfig
    'PROXY',               # storage collision, slot issues
    'PERMIT',              # EIP-2612 abuse
    'FLASH_LOAN',          # callback / abuse
    'VAULT',               # ERC4626-specific
    'OTHER',               # ungrouped
}


# Map: tool's check name → canonical category
_TOOL_CHECK_TO_CANONICAL: Dict[str, str] = {
    # ── ChainEDR internal ──
    'cross_function_reentrancy':       'REENTRANCY',
    'readonly_reentrancy':             'REENTRANCY',
    'reentrancy_eth':                  'REENTRANCY',
    'reentrancy_no_eth':               'REENTRANCY',
    'external_acl_delegation':         'ACCESS_CONTROL',
    'access_control':                  'ACCESS_CONTROL',
    'stale_oracle_data':               'ORACLE',
    'missing_sequencer_check':         'ORACLE',
    'cross_contract_oracle_taint':     'ORACLE',
    'oracle_manipulation':             'ORACLE',
    'silent_truncation':               'INTEGER',
    'integer_overflow':                'INTEGER',
    'silent_overflow':                 'INTEGER',
    'unchecked_calls':                 'EXTERNAL_CALL',
    'unchecked_transfer':              'EXTERNAL_CALL',
    'dangerous_transfer':              'EXTERNAL_CALL',
    'insecure_randomness':             'RANDOMNESS',
    'unbounded_loops':                 'DOS',
    'unbounded_loop':                  'DOS',
    'gas_griefing':                    'DOS',
    'sandwich_vulnerability':          'FRONTRUNNING',
    'missing_slippage_protection':     'FRONTRUNNING',
    'param_ramp_sandwich':             'FRONTRUNNING',
    'safety_buffer_waterfall':         'LOGIC',
    'rounding_direction':              'LOGIC',
    'rounding_asymmetry':              'LOGIC',
    'zero_min_internal':               'LOGIC',
    'root_precision':                  'LOGIC',
    'vault_inflation':                 'VAULT',
    'permit_surface':                  'PERMIT',
    'flash_loan_callback':             'FLASH_LOAN',
    'replay_protection':               'SIGNATURE',
    'abi_decode_risks':                'SIGNATURE',
    'bridge_address_validation_gap':   'BRIDGE',
    'zk_verifier_misconfig':           'ZK',
    'initialization':                  'INITIALIZATION',

    # ── Slither detector IDs ──
    'reentrancy-eth':                  'REENTRANCY',
    'reentrancy-no-eth':               'REENTRANCY',
    'reentrancy-benign':               'REENTRANCY',
    'reentrancy-events':               'REENTRANCY',
    'reentrancy-unlimited-gas':        'REENTRANCY',
    'suicidal':                        'ACCESS_CONTROL',
    'arbitrary-send-eth':              'ACCESS_CONTROL',
    'arbitrary-send-erc20':            'ACCESS_CONTROL',
    'controlled-delegatecall':         'DELEGATECALL',
    'unchecked-transfer':              'EXTERNAL_CALL',
    'unchecked-lowlevel':              'EXTERNAL_CALL',
    'unchecked-send':                  'EXTERNAL_CALL',
    'weak-prng':                       'RANDOMNESS',
    'tautology':                       'INTEGER',
    'integer-overflow':                'INTEGER',
    'abi-encodepacked-collision':      'SIGNATURE',
    'calls-loop':                      'DOS',
    'uninitialized-state':             'INITIALIZATION',
    'uninitialized-storage':           'PROXY',
    'shadowing-state':                 'PROXY',
    'storage-array-deletion':          'PROXY',

    # ── Wake detector names (common ones) ──
    'reentrancy':                      'REENTRANCY',
    'unchecked-return-value':          'EXTERNAL_CALL',
    'tx-origin':                       'ACCESS_CONTROL',
    'unsafe-delegatecall':             'DELEGATECALL',
    'unprotected-selfdestruct':        'ACCESS_CONTROL',

    # ── Mythril SWC IDs ──
    'SWC-100':                         'ACCESS_CONTROL',
    'SWC-101':                         'INTEGER',
    'SWC-104':                         'EXTERNAL_CALL',
    'SWC-105':                         'ACCESS_CONTROL',
    'SWC-106':                         'ACCESS_CONTROL',
    'SWC-107':                         'REENTRANCY',
    'SWC-108':                         'PROXY',
    'SWC-110':                         'LOGIC',
    'SWC-112':                         'DELEGATECALL',
    'SWC-114':                         'FRONTRUNNING',
    'SWC-115':                         'ACCESS_CONTROL',
    'SWC-116':                         'ORACLE',
    'SWC-117':                         'SIGNATURE',
    'SWC-118':                         'INITIALIZATION',
    'SWC-119':                         'PROXY',
    'SWC-120':                         'RANDOMNESS',
    'SWC-122':                         'SIGNATURE',
    'SWC-128':                         'DOS',
}


def canonicalize_check(check: str) -> str:
    """Return canonical category for any tool's check name."""
    if not check:
        return 'OTHER'
    # Normalize: lowercase, strip prefixes like '[Slither/' or '[Wake/'
    norm = check.lower().strip()
    # Try direct lookup first
    if check in _TOOL_CHECK_TO_CANONICAL:
        return _TOOL_CHECK_TO_CANONICAL[check]
    if norm in _TOOL_CHECK_TO_CANONICAL:
        return _TOOL_CHECK_TO_CANONICAL[norm]
    # Bracketed prefix: [Slither/reentrancy-eth] → reentrancy-eth
    if '[' in check and '/' in check and ']' in check:
        inner = check.split('/', 1)[1].split(']')[0]
        if inner.lower() in {k.lower(): v for k, v in _TOOL_CHECK_TO_CANONICAL.items()}:
            for k, v in _TOOL_CHECK_TO_CANONICAL.items():
                if k.lower() == inner.lower():
                    return v
    # Fuzzy: substring match
    for keyword, cat in [
        ('reentrancy', 'REENTRANCY'), ('reentrant', 'REENTRANCY'),
        ('oracle', 'ORACLE'), ('stale', 'ORACLE'),
        ('overflow', 'INTEGER'), ('truncat', 'INTEGER'),
        ('access', 'ACCESS_CONTROL'), ('suicid', 'ACCESS_CONTROL'),
        ('unchecked', 'EXTERNAL_CALL'), ('arbitrary-send', 'ACCESS_CONTROL'),
        ('delegatecall', 'DELEGATECALL'),
        ('prng', 'RANDOMNESS'), ('random', 'RANDOMNESS'),
        ('dos', 'DOS'), ('loop', 'DOS'),
        ('slippage', 'FRONTRUNNING'), ('sandwich', 'FRONTRUNNING'),
        ('signature', 'SIGNATURE'), ('replay', 'SIGNATURE'),
        ('bridge', 'BRIDGE'), ('zk', 'ZK'), ('verifier', 'ZK'),
        ('vault', 'VAULT'), ('permit', 'PERMIT'),
        ('flash', 'FLASH_LOAN'),
    ]:
        if keyword in norm:
            return cat
    return 'OTHER'


def _dedup_key(finding: Dict) -> Tuple[str, str, str, str]:
    """
    Canonical key for dedup: (category, file_basename, function_name, desc_hash).

    Critical safety: if file AND function are both empty, the finding has
    no location grounding — collapse only with other findings whose check
    AND description-fingerprint also match (i.e. truly identical detections).

    This prevents collapsing 37 distinct silent_truncation findings (each
    in different functions/files we didn't capture) into one bucket.
    """
    cat = canonicalize_check(finding.get('check', ''))
    file_full = finding.get('file', '') or finding.get('filename', '') or ''
    file_base = Path(file_full).name if file_full else ''
    fn = (finding.get('function', '') or finding.get('function_sig', '')).strip()

    # Fingerprint description for groundless findings — first 80 chars
    desc = (finding.get('description', '') or '')[:80].lower()

    if not file_base and not fn:
        # No location → treat description fingerprint as the discriminator
        return (cat, '', '', desc)
    # Have location → use it, ignore desc to allow merging identical bugs
    # detected by different tools
    return (cat, file_base.lower(), fn.lower(), '')


def deduplicate_across_tools(findings: List[Dict]) -> List[Dict]:
    """
    Merge findings that share the same canonical key across different tools.

    The merged finding:
      - keeps the HIGHEST-severity version's metadata as base
      - gets `detected_by`: List[str] = sorted unique source_tools
      - gets `consensus_confidence`: float ≥ original, boosted per extra tool
      - keeps all original descriptions in `tool_descriptions: Dict[str, str]`

    Findings with no matching key pass through unchanged (detected_by=[their_tool]).
    """
    if not findings:
        return []

    # Bucket by canonical key
    buckets: Dict[Tuple[str, str, str], List[Dict]] = defaultdict(list)
    for f in findings:
        buckets[_dedup_key(f)].append(f)

    sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

    def _sev_idx(s: str) -> int:
        try:
            return sev_order.index(s.upper())
        except ValueError:
            return 99

    merged: List[Dict] = []
    for key, group in buckets.items():
        if len(group) == 1:
            f = dict(group[0])
            f.setdefault('detected_by', [f.get('source_tool', 'chainedr')])
            f.setdefault('consensus_confidence', f.get('confidence', 0.5))
            merged.append(f)
            continue

        # Pick the most severe as base, fold the rest
        group_sorted = sorted(group, key=lambda x: _sev_idx(x.get('severity', 'LOW')))
        base = dict(group_sorted[0])

        tools = sorted({f.get('source_tool', 'chainedr') for f in group})
        base['detected_by'] = tools
        base['tool_descriptions'] = {
            f.get('source_tool', 'chainedr'): (f.get('description', '') or '')[:300]
            for f in group
        }
        # Consensus boost: +10% per additional tool, capped at 0.95
        base_conf = max((f.get('confidence', 0.5) for f in group), default=0.5)
        n_extra = max(0, len(tools) - 1)
        base['consensus_confidence'] = round(
            min(0.95, base_conf + 0.10 * n_extra), 3
        )
        base['canonical_category'] = key[0]
        merged.append(base)

    # Sort by severity (most severe first)
    merged.sort(key=lambda f: _sev_idx(f.get('severity', 'LOW')))
    return merged


def consensus_report(findings: List[Dict]) -> str:
    """Pretty-print which tools agreed on what."""
    deduped = deduplicate_across_tools(findings)
    multi_tool = [f for f in deduped if len(f.get('detected_by', [])) > 1]

    lines = [
        f"{'─'*64}",
        "  Cross-Tool Consensus",
        f"{'─'*64}",
        f"  Total unique findings:  {len(deduped)}",
        f"  Multi-tool consensus:   {len(multi_tool)}",
        f"  Single-tool only:       {len(deduped) - len(multi_tool)}",
    ]
    if multi_tool:
        lines.append("\n  Consensus findings (high confidence):")
        for f in multi_tool[:10]:
            tools = ', '.join(f.get('detected_by', []))
            chk = f.get('check', '?')
            cat = f.get('canonical_category', '?')
            conf = f.get('consensus_confidence', 0)
            lines.append(
                f"    [{f.get('severity', '?')}] {cat:18s} {chk:30s}  "
                f"agreed by [{tools}] (conf={conf:.0%})"
            )
    lines.append(f"{'─'*64}")
    return '\n'.join(lines)
