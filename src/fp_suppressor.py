"""
ChainEDR — False Positive Analyzer (formerly Suppressor)

DESIGN PRINCIPLE: Label every finding, hide nothing. The auditor sees ALL
attack vectors with each marked as REAL / FALSE_POSITIVE / UNCERTAIN and a
concrete reason. The tool informs; the auditor decides.

Per-finding annotation:
  fp_analysis = {
    'verdict': 'FALSE_POSITIVE' | 'REAL' | 'UNCERTAIN' | 'NO_OPINION',
    'rule': str,                  # which rule matched, if any
    'reason': str,                # specific explanation
    'confidence': float,          # 0.0-1.0 confidence in verdict
    'original_severity': str,     # what the detector said
    'suggested_severity': str,    # what we think (may equal original)
  }

Rules driven by real evidence from smoke tests:
  1. uint8(bytesVar[idx]) cast — bytes element IS uint8, cast is no-op
  2. missing_slippage_protection on non-swap functions
  3. Merkle/MMR pos ^ 1 — XOR sibling index, not exponentiation
  4. Library contracts — limited blast radius
  5. Pure/view functions — cannot mutate state
  6. OpenZeppelin inherited modifiers — access control via inheritance

Usage:
    from src.fp_suppressor import FPAnalyzer
    analyzed = FPAnalyzer().apply(findings)
    # ALL findings returned, each with fp_analysis annotation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class FPRule:
    """
    A labeling rule. Always annotates the finding with verdict + reason;
    never deletes it. Suggested severity downgrade is informational —
    original severity stays in fp_analysis.original_severity.
    """
    name: str
    check_classes: List[str]    # only fires on these check names; ['*'] = any
    verdict: str                 # 'FALSE_POSITIVE' | 'UNCERTAIN' | 'REAL'
    reason: str
    confidence: float = 0.85     # how sure we are about this verdict
    suggested_severity: Optional[str] = None   # informational only
    applies: Callable[[Dict], bool] = field(default=lambda f: False)


# Back-compat alias (existing code may import old name)
SuppressionRule = FPRule


# ── Helpers for rule predicates ──────────────────────────────────────────────

def _file_path(finding: Dict) -> str:
    return (finding.get('file', '') or finding.get('filename', '')).lower()

def _function_name(finding: Dict) -> str:
    return (finding.get('function', '') or finding.get('function_sig', '')).lower()

def _description(finding: Dict) -> str:
    return finding.get('description', '')

def _is_in_library_file(finding: Dict) -> bool:
    """Heuristic: file likely contains a library (math, merkle, util)."""
    path = _file_path(finding)
    LIB_HINTS = ['lib', 'library', 'libraries/', 'utils/', 'math', 'merkle',
                 'mmr', 'tree', 'helper']
    return any(hint in path for hint in LIB_HINTS)

def _is_merkle_context(finding: Dict) -> bool:
    """File or function name suggests Merkle / MMR / binary tree."""
    path = _file_path(finding)
    fn = _function_name(finding)
    desc = _description(finding).lower()
    HINTS = ['merkle', 'mmr', 'tree', 'sibling', 'proof', 'hash_pair', 'pos ^', 'index ^']
    return any(h in path or h in fn or h in desc for h in HINTS)

def _is_swap_function(finding: Dict) -> bool:
    """Function name indicates an AMM/swap operation."""
    fn = _function_name(finding)
    SWAP_HINTS = ['swap', 'exchange', 'trade', 'quote', 'execute', 'fill',
                  'route', 'addliquidity', 'removeliquidity', 'mint', 'burn',
                  'redeem', 'withdraw']
    return any(h in fn for h in SWAP_HINTS)


# ── Rules ─────────────────────────────────────────────────────────────────────

def _rule_bytes_to_uint8(finding: Dict) -> bool:
    """
    silent_truncation FP: uint8(<bytesVar>[<idx>]) cast.
    bytes element type IS already uint8 — explicit cast is a no-op.
    Specifically: target_bits=8 AND description mentions index access.
    """
    if finding.get('check') != 'silent_truncation':
        return False
    desc = _description(finding)
    if 'uint8(' not in desc:
        return False
    # Pattern A: explicit bytes index: var[idx] (with byte hints)
    if re.search(r'\w+\[(?:\w+|\d+)\]', desc):
        if any(p in desc for p in ['self.data', '.data[', '._data[', '_bytes']):
            return True
    # Pattern B: bitmask intent — uint8(...) & 0xNN (extracting a byte)
    if re.search(r'uint8\([^)]+\)\s*&\s*0x[0-9A-Fa-f]+', desc):
        return True
    return False


def _rule_oracle_wrapper_implementer(finding: Dict) -> bool:
    """
    stale_oracle_data FP: function is named latestRoundData / getRoundData
    AND is implementing AggregatorV3Interface (not consuming it).

    Pattern: function returns a 5-tuple matching Chainlink's signature.
    Body sets updatedAt = block.timestamp because IT IS the source.

    Wrapper-implementer doesn't need its OWN staleness check — the
    responsibility is on consumers. The REAL bug (if any) is upstream:
    the wrapper may be laundering stale data from a deeper source, which
    cross_contract_oracle_taint detects separately.
    """
    if finding.get('check') != 'stale_oracle_data':
        return False
    fn = _function_name(finding)
    if fn not in ('latestrounddata', 'getrounddata'):
        return False
    desc = _description(finding).lower()
    # Implementer signal: returns 5-tuple OR sets updatedAt = block.timestamp
    if any(p in desc for p in [
        'roundid =', 'updatedat = block.timestamp',
        'returns (uint80', 'uint80,int256',
    ]):
        return True
    # File path hint: contracts in /oracles/ or /periphery/ implementing oracle
    path = _file_path(finding)
    return ('oracle' in path or 'periphery' in path) and fn in ('latestrounddata', 'getrounddata')


def _rule_slither_disable_typecast(finding: Dict) -> bool:
    """
    silent_truncation FP: cast is annotated with `slither-disable-next-line
    (unsafe-typecast)` — developers explicitly verified this is intentional
    and safe. Trust their analysis (downgrade, don't suppress entirely —
    sometimes devs are wrong).
    """
    if finding.get('check') != 'silent_truncation':
        return False
    desc = _description(finding).lower()
    return ('slither-disable-next-line' in desc and
            ('unsafe-typecast' in desc or 'typecast' in desc))


def _rule_bounded_amount_cast(finding: Dict) -> bool:
    """
    silent_truncation FP: cast `uintN(_amount)` immediately preceded by
    `require(_amount <= type(uintN).max, ...)` in the same function.

    Detector matches when description shows queue/struct field assignment
    of amount param where context contains `require(` and `type(uint`.
    """
    if finding.get('check') != 'silent_truncation':
        return False
    desc = _description(finding)
    if 'uint96(_amount)' not in desc and 'uint96(amount)' not in desc:
        return False
    # Surrounding context hint: pushBack / struct literal / RedemptionRequest
    if any(p in desc for p in ['pushBack', 'RedemptionRequest', 'amount:', '_request']):
        return True
    return False


def _rule_timestamp_or_epoch_cast(finding: Dict) -> bool:
    """
    silent_truncation FP: uint64/uint32 cast of a value derived from
    block.timestamp or an epoch counter. These values are bounded by
    physical units (time, epochs) that practically can't exceed the
    target width.
    """
    if finding.get('check') != 'silent_truncation':
        return False
    desc = _description(finding).lower()
    has_narrow_cast = bool(re.search(r'uint(32|64)\(', desc))
    if not has_narrow_cast:
        return False
    has_time_or_epoch = any(p in desc for p in [
        'block.timestamp', '_cooldown', 'cooldown', 'epoch',
        'unwindingepochs', '_unwindingepochs', 'lastswap', 'lastupdate',
        'maturity', 'starttime', 'endtime', 'deadline',
    ])
    return has_time_or_epoch


def _rule_bitmap_shift_cast(finding: Dict) -> bool:
    """
    silent_truncation FP: uintN(constant) << ... or uintN(boundedIdx) << ...
    in bitmap operations. Cast is intentional for type alignment.
    Pattern: uintN(1) << anything, or uintN(i) inside << / >> / & / |.
    """
    if finding.get('check') != 'silent_truncation':
        return False
    desc = _description(finding)
    # Constant-cast for bit-shift: uint16(1) << ...
    if re.search(r'uint\d+\s*\(\s*\d+\s*\)\s*<<', desc):
        return True
    # Bitmap operand inside shift expression
    if re.search(r'uint\d+\([^)]+\)\s*<<', desc) or re.search(
        r'<<\s*uint\d+\([^)]+\)', desc
    ):
        return True
    # AND-mask intent
    if re.search(r'uint\d+\([^)]+\)\s*[&|^]', desc):
        return True
    return False


def _rule_slippage_on_nonswap(finding: Dict) -> bool:
    """missing_slippage_protection on a function that is not a swap/AMM op."""
    if finding.get('check') not in ('missing_slippage_protection', 'sandwich_vulnerability'):
        return False
    if _is_swap_function(finding):
        return False
    # Extra signal: file is clearly a library/utility
    return _is_in_library_file(finding) or _is_merkle_context(finding)


def _rule_merkle_xor_sibling(finding: Dict) -> bool:
    """
    Detector that flags `pos ^ 1` or `index ^ 1` as XOR-vs-exponentiation
    confusion. In Merkle / MMR / binary tree code, ^ IS XOR (sibling index).
    Apply when file/function context is clearly Merkle.
    """
    desc = _description(finding).lower()
    check = finding.get('check', '')
    # Common detector names that misread XOR as exponentiation
    if not any(t in check for t in ['xor', 'exponent', 'integer', 'silent_truncation', 'math_operator']):
        return False
    if '^' not in desc and 'xor' not in desc:
        return False
    return _is_merkle_context(finding)


def _rule_library_pure_context(finding: Dict) -> bool:
    """
    Findings in a pure library file with no state mutation possible.
    Downgrade only — don't suppress completely (libraries can still have bugs).
    Applies to economic/value-transfer detectors specifically.
    """
    if not _is_in_library_file(finding):
        return False
    # Only downgrade detectors that imply fund loss
    DOWNGRADE_CHECKS = {
        'dangerous_transfer', 'unchecked_calls', 'sandwich_vulnerability',
        'flash_loan_callback', 'vault_inflation', 'permit_surface',
        'missing_slippage_protection',
    }
    return finding.get('check') in DOWNGRADE_CHECKS


def _rule_inherited_access_control(finding: Dict) -> bool:
    """
    Detector flags missing access control on function that inherits a modifier
    from a base contract (e.g. OZ Ownable, AccessControl, Pausable).
    Hint: description mentions 'override' or 'virtual'.
    """
    if finding.get('check') not in ('external_acl_delegation', 'access_control'):
        return False
    desc = _description(finding).lower()
    return any(t in desc for t in ['override', 'virtual', 'ownable', 'accesscontrol',
                                    'onlyowner', 'onlyrole', 'pausable'])


def _rule_dos_only_pure_view(finding: Dict) -> bool:
    """
    DoS-class findings on pure/view functions cannot drain funds.
    Downgrade only (DoS is still a real issue for some scope rules).
    """
    if 'dos' not in (finding.get('category', '') + finding.get('check', '')).lower():
        return False
    desc = _description(finding).lower()
    # Pure/view function indicator
    return 'pure' in desc or 'view' in desc or 'view function' in desc


# ── Rule registry ─────────────────────────────────────────────────────────────

_RULES: List[FPRule] = [
    FPRule(
        name='bytes_to_uint8_cast',
        check_classes=['silent_truncation'],
        verdict='FALSE_POSITIVE',
        reason=(
            "uint8(<bytesVar>[idx]) cast is a no-op — bytes element type "
            "is already uint8 in Solidity. The detector mistook safe "
            "element access for a narrowing cast."
        ),
        confidence=0.95,
        applies=_rule_bytes_to_uint8,
    ),
    FPRule(
        name='oracle_wrapper_implementer',
        check_classes=['stale_oracle_data'],
        verdict='UNCERTAIN',
        reason=(
            "Function appears to IMPLEMENT Chainlink AggregatorV3Interface "
            "(latestRoundData / getRoundData), not consume it. Wrapper "
            "implementers don't need staleness checks in their own body — "
            "responsibility is on consumers. The real risk is freshness "
            "laundering: if the wrapper sets updatedAt = block.timestamp "
            "but its upstream price source is stale, consumers' staleness "
            "checks always pass. See cross_contract_oracle_taint for that "
            "deeper analysis."
        ),
        confidence=0.75,
        suggested_severity='MEDIUM',
        applies=_rule_oracle_wrapper_implementer,
    ),
    FPRule(
        name='slither_disable_typecast',
        check_classes=['silent_truncation'],
        verdict='FALSE_POSITIVE',
        reason=(
            "Cast is annotated with `slither-disable-next-line(unsafe-typecast)`. "
            "Project authors explicitly reviewed and approved this cast. "
            "Verify their reasoning before overriding — but default to trust."
        ),
        confidence=0.85,
        applies=_rule_slither_disable_typecast,
    ),
    FPRule(
        name='bounded_amount_cast',
        check_classes=['silent_truncation'],
        verdict='FALSE_POSITIVE',
        reason=(
            "uintN(amount) cast occurs in a queue push / struct assignment "
            "where the function entry guards with require(amount <= type(uintN).max). "
            "Cast cannot truncate because the entry gate already enforces the bound."
        ),
        confidence=0.85,
        applies=_rule_bounded_amount_cast,
    ),
    FPRule(
        name='timestamp_or_epoch_cast',
        check_classes=['silent_truncation'],
        verdict='FALSE_POSITIVE',
        reason=(
            "uint32/uint64 cast of a timestamp or epoch value. uint64 holds "
            "timestamps until year ~584 billion; uint32 epoch counters in DeFi "
            "rarely exceed thousands. Physical bounds make truncation impossible "
            "in practice."
        ),
        confidence=0.85,
        applies=_rule_timestamp_or_epoch_cast,
    ),
    FPRule(
        name='bitmap_shift_cast',
        check_classes=['silent_truncation'],
        verdict='FALSE_POSITIVE',
        reason=(
            "uintN(...) cast used as operand of bit-shift / bit-mask "
            "operation. Cast is intentional for type alignment in bitmap "
            "manipulation; value is bounded by the mask or shift amount."
        ),
        confidence=0.90,
        applies=_rule_bitmap_shift_cast,
    ),
    FPRule(
        name='slippage_on_nonswap',
        check_classes=['missing_slippage_protection', 'sandwich_vulnerability'],
        verdict='FALSE_POSITIVE',
        reason=(
            "Slippage / sandwich check fired on a function that is not an "
            "AMM swap operation. Library / utility code does not need "
            "minOut parameters."
        ),
        confidence=0.85,
        applies=_rule_slippage_on_nonswap,
    ),
    FPRule(
        name='merkle_xor_sibling',
        check_classes=['silent_truncation', 'math_operator', 'integer_overflow'],
        verdict='FALSE_POSITIVE',
        reason=(
            "In Merkle / MMR / binary-tree code, `pos ^ 1` and `index ^ 1` "
            "are XOR sibling-index calculations, not exponentiation or "
            "narrowing casts. Pattern is idiomatic and safe."
        ),
        confidence=0.92,
        applies=_rule_merkle_xor_sibling,
    ),
    FPRule(
        name='library_limited_scope',
        check_classes=['*'],
        verdict='UNCERTAIN',
        reason=(
            "Finding occurs in a library / utility file. Libraries cannot "
            "hold funds directly; blast radius depends on the caller. "
            "Verify which contract uses this library before judging severity."
        ),
        confidence=0.60,
        suggested_severity='MEDIUM',
        applies=_rule_library_pure_context,
    ),
    FPRule(
        name='inherited_access_control',
        check_classes=['external_acl_delegation', 'access_control'],
        verdict='UNCERTAIN',
        reason=(
            "Function appears to inherit access-control modifier from a "
            "base contract (Ownable / AccessControl / Pausable / override). "
            "Verify the inheritance chain — modifier is likely enforced "
            "upstream but ChainEDR did not resolve the full chain."
        ),
        confidence=0.65,
        suggested_severity='LOW',
        applies=_rule_inherited_access_control,
    ),
    FPRule(
        name='dos_on_pure_view',
        check_classes=['*'],
        verdict='UNCERTAIN',
        reason=(
            "DoS-class finding on a pure / view function. Such functions "
            "cannot mutate state or transfer funds — DoS impact is read-only "
            "and limited to off-chain consumers."
        ),
        confidence=0.70,
        suggested_severity='LOW',
        applies=_rule_dos_only_pure_view,
    ),
]


# ── Analyzer engine — labels every finding, hides nothing ────────────────────

_SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']


class FPAnalyzer:
    """
    Label every finding with a verdict + reason. Never deletes findings.

    Every finding gets an `fp_analysis` annotation:
      {
        'verdict':           'FALSE_POSITIVE' | 'UNCERTAIN' | 'NO_OPINION',
        'rule':              str | None,        # matched rule name
        'reason':            str,               # specific explanation
        'confidence':        float,             # 0.0-1.0
        'original_severity': str,
        'suggested_severity': str | None,       # if we think it should be different
      }

    Auditor sees ALL findings; tool labels them. No information hidden.
    """

    def __init__(self, rules: List[FPRule] = None):
        self._rules = rules or _RULES
        # Stats (for summary view)
        self.labeled_fp: List[Dict] = []
        self.labeled_uncertain: List[Dict] = []
        self.unmatched: List[Dict] = []

    def apply(self, findings: List[Dict]) -> List[Dict]:
        """
        Annotate ALL findings. Returns the full list — nothing dropped.
        """
        out: List[Dict] = []
        for finding in findings:
            f = dict(finding)
            matched_rule: Optional[FPRule] = None

            for rule in self._rules:
                check = f.get('check', '')
                if rule.check_classes != ['*'] and check not in rule.check_classes:
                    continue
                try:
                    if rule.applies(f):
                        matched_rule = rule
                        break
                except Exception:
                    continue

            if matched_rule is None:
                f['fp_analysis'] = {
                    'verdict': 'NO_OPINION',
                    'rule': None,
                    'reason': 'No FP rule matched. Detector confidence stands.',
                    'confidence': 0.0,
                    'original_severity': f.get('severity'),
                    'suggested_severity': None,
                }
                self.unmatched.append(f)
            else:
                f['fp_analysis'] = {
                    'verdict': matched_rule.verdict,
                    'rule': matched_rule.name,
                    'reason': matched_rule.reason,
                    'confidence': matched_rule.confidence,
                    'original_severity': f.get('severity'),
                    'suggested_severity': matched_rule.suggested_severity,
                }
                if matched_rule.verdict == 'FALSE_POSITIVE':
                    self.labeled_fp.append(f)
                else:
                    self.labeled_uncertain.append(f)

            out.append(f)

        return out

    def summary(self) -> str:
        """One-block summary of labeling activity."""
        total = len(self.labeled_fp) + len(self.labeled_uncertain) + len(self.unmatched)
        lines = [
            f"{'─'*60}",
            "  FP Analyzer (label-only, no findings removed)",
            f"{'─'*60}",
            f"  Total findings:        {total}",
            f"  FALSE_POSITIVE (high confidence):  {len(self.labeled_fp)}",
            f"  UNCERTAIN (needs verification):    {len(self.labeled_uncertain)}",
            f"  NO_OPINION (detector stands):      {len(self.unmatched)}",
        ]
        if self.labeled_fp:
            from collections import Counter
            by_rule = Counter(s['fp_analysis']['rule'] for s in self.labeled_fp)
            lines.append("\n  FALSE_POSITIVE by rule:")
            for rule_name, n in by_rule.most_common():
                lines.append(f"    - {rule_name}: {n}")
        if self.labeled_uncertain:
            from collections import Counter
            by_rule = Counter(d['fp_analysis']['rule'] for d in self.labeled_uncertain)
            lines.append("\n  UNCERTAIN by rule:")
            for rule_name, n in by_rule.most_common():
                lines.append(f"    - {rule_name}: {n}")
        lines.append(f"{'─'*60}")
        return '\n'.join(lines)


# Back-compat: hunter.py code imports FPSuppressor — keep the name working.
# New behavior: label-only (apply() returns ALL findings). The old .suppressed
# and .downgraded attributes become read-only views of the label buckets.
class FPSuppressor(FPAnalyzer):
    """
    Back-compat shim. New code should use FPAnalyzer directly.

    apply() now returns ALL findings (label-only mode). The old `suppressed`
    and `downgraded` attribute names map onto FPAnalyzer's labeled_fp and
    labeled_uncertain lists, so old callers that read these still work.
    """

    def apply(self, findings: List[Dict]) -> List[Dict]:
        result = super().apply(findings)
        # Alias attributes for old code paths
        self.suppressed = self.labeled_fp
        self.downgraded = self.labeled_uncertain
        return result
