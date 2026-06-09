"""ChainEDR Invariant Fuzzer v1.0

Experimental static detector for economic invariant violations.

These detectors explore DeFi-specific accounting and economic-invariant
patterns. Treat the output as research leads unless backed by a harness,
state trace, or manual audit argument.

Detectors:
  1. WATERFALL_CLIFF       - Partial resource not consumed before passing loss down waterfall
  2. SIBLING_ASYMMETRY     - Paired functions (positive/negative, deposit/withdraw) handle
                             shared state differently (one partial, one all-or-nothing)
  3. ACCOUNTING_GAP        - Token flow inputs != outputs in a function branch
  4. THRESHOLD_CLIFF       - Discontinuous behavior at >= boundary (1 wei = 100x difference)
  5. ORPHANED_RESOURCE     - Resource (buffer, reserve) exists but is bypassed in loss path
  6. FEE_ROUNDING_BIAS     - Both fee and user share divided independently → systematic drift
  7. REWARD_CLIFF          - Epoch-based rewards via block.timestamp / N → 1-second cliff
  8. GRIEFABLE_UPDATER     - Unchecked external read stored to state → attacker can grief

Historical note: several rules were motivated by real contest-style accounting
bugs, but this module is not part of the focused reviewer 7702 proof path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple, Dict


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class InvariantSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class InvariantFinding:
    severity:    InvariantSeverity
    detector:    str
    title:       str
    description: str
    location:    str
    confidence:  float = 0.0   # 0-1
    fix:         str   = ""
    poc:         str   = ""    # minimal PoC pseudocode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STRIP_COMMENTS_RE = re.compile(
    r'//[^\n]*|/\*.*?\*/', re.DOTALL
)

def _strip_comments(src: str) -> str:
    return _STRIP_COMMENTS_RE.sub(' ', src)


def _extract_body(src: str, open_brace_pos: int) -> str:
    """Extract everything between { } starting at open_brace_pos."""
    depth = 0
    start = None
    for i in range(open_brace_pos, len(src)):
        if src[i] == '{':
            if depth == 0:
                start = i + 1
            depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                return src[start:i]
    return src[open_brace_pos:]


_FN_RE = re.compile(
    r'\b(?:function\s+(\w+)|(?P<ctor>constructor))\s*\([^)]*\)[^{]*\{',
    re.MULTILINE,
)

def _extract_functions(src: str) -> List[Dict]:
    """Return list of {name, body, line} dicts."""
    clean = _strip_comments(src)
    fns = []
    for m in _FN_RE.finditer(clean):
        name = m.group(1) if m.group(1) else 'constructor'
        body = _extract_body(clean, m.end() - 1)
        line = clean[:m.start()].count('\n') + 1
        fns.append({'name': name, 'body': body, 'line': line})
    return fns


# ---------------------------------------------------------------------------
# Detector 1: Waterfall Cliff
#
# Pattern: if (resource >= loss) { consume_all(loss); return; }
#          // NO else: consume_partial(resource); loss -= resource;
#
# This is the exact infiniFi _handleNegativeYield bug class.
# ---------------------------------------------------------------------------

# Patterns that indicate "consume all of B" (burn, apply, reduce)
_CONSUME_ALL_RE = re.compile(
    r'\b(?:burn|applyLoss(?:es)?|reduce|slash|deduct|subtract|consume|absorb)\s*\(',
    re.IGNORECASE,
)

# Patterns that look like resource guard: if (X >= Y) or if (Y <= X)
_RESOURCE_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*(>=|<=|==)\s*(\w+)\s*\)',
    re.MULTILINE,
)

def detect_waterfall_cliff(src: str) -> List[InvariantFinding]:
    """
    Find: if (buffer >= loss) { burn(loss); return; }
          // falls through WITHOUT burning buffer when buffer < loss

    The tell: a guarded consume-all + early return, with NO partial consume
    in the else/fallthrough path that reduces the same variable.
    """
    findings = []
    clean = _strip_comments(src)
    fns   = _extract_functions(src)

    for fn in fns:
        body  = _strip_comments(fn['body'])
        # Find all early-return blocks after a resource guard
        for guard in _RESOURCE_GUARD_RE.finditer(body):
            # Extract the if-block body
            if_body = _extract_body(body, guard.end())

            # Must have: (1) a consume call and (2) a return inside the if-block
            if not _CONSUME_ALL_RE.search(if_body):
                continue
            if 'return' not in if_body:
                continue

            # The guard variables (potential buffer/loss pair)
            left_var  = guard.group(1)
            right_var = guard.group(3)
            op        = guard.group(2)

            # After the if-block, check if the "buffer" variable is consumed
            # in the fallthrough (partial consumption)
            after_if = body[guard.end() + len(if_body):]

            # Look for: partial consume of the buffer variable in fallthrough
            partial_consume = re.search(
                rf'\b(?:burn|applyLoss(?:es)?|reduce|slash|deduct|subtract|consume|absorb)\s*\([^)]*\b{re.escape(left_var)}\b',
                after_if, re.IGNORECASE,
            )

            if partial_consume:
                continue  # Correct: partial consumption exists

            # Also skip if the fallthrough subtracts the buffer from the loss
            # e.g.: loss -= buffer;  or  _negativeYield -= safetyBuffer;
            subtract_pattern = re.search(
                rf'\b(?:{re.escape(right_var)}|_?\w*[Ll]oss\w*|_?\w*[Yy]ield\w*)\b\s*-=\s*\b{re.escape(left_var)}\b',
                after_if,
            )
            if subtract_pattern:
                continue  # Correct: loss reduced by buffer

            # No partial consumption found — this is the waterfall cliff
            findings.append(InvariantFinding(
                severity=InvariantSeverity.HIGH,
                detector='WATERFALL_CLIFF',
                title=f"Waterfall cliff in {fn['name']}(): `{left_var}` not partially consumed",
                description=(
                    f"`{fn['name']}()` guards on `{left_var} {op} {right_var}`, fully "
                    f"consumes `{right_var}` when true, but does NOT partially consume "
                    f"`{left_var}` in the fallthrough path. The full loss is applied "
                    f"to the next layer without first exhausting `{left_var}`. "
                    f"A 1-wei difference in `{left_var}` can cause orders-of-magnitude "
                    f"difference in downstream losses (cliff behavior)."
                ),
                location=f"{fn['name']}():L{fn['line']}",
                confidence=0.80,
                fix=(
                    f"Before the fallthrough, add:\n"
                    f"  uint256 absorbed = Math.min({left_var}, {right_var});\n"
                    f"  if (absorbed > 0) {{ burn(absorbed); {right_var} -= absorbed; }}\n"
                    f"  if ({right_var} == 0) return;"
                ),
                poc=(
                    f"// 1-wei cliff PoC:\n"
                    f"// Case A: {left_var} = X     → loss absorbed fully, downstream = 0\n"
                    f"// Case B: {left_var} = X - 1 → {left_var} untouched, downstream = full loss\n"
                    f"// 1 token difference = full loss difference"
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Detector 2: Sibling Asymmetry
#
# Find function pairs with mirrored semantics (positive/negative, add/remove,
# deposit/withdraw, mint/burn) and compare how they handle shared state vars.
# ---------------------------------------------------------------------------

_SIBLING_PAIRS = [
    ('positive', 'negative'),
    ('deposit',  'withdraw'),
    ('mint',     'burn'),
    ('add',      'remove'),
    ('increase', 'decrease'),
    ('stake',    'unstake'),
    ('lock',     'unlock'),
    ('supply',   'redeem'),
    ('fill',     'drain'),
    ('accrue',   'distribute'),
]

def _fn_key(name: str) -> Optional[Tuple[str, str]]:
    """Return (pair_root, side) if name matches a sibling pattern, else None."""
    lower = name.lower()
    for a, b in _SIBLING_PAIRS:
        if a in lower:
            return (lower.replace(a, ''), a)
        if b in lower:
            return (lower.replace(b, ''), b)
    return None


def _shared_state_vars(body_a: str, body_b: str) -> List[str]:
    """Return state variable names written in BOTH function bodies."""
    write_re = re.compile(r'\b(\w+)\s*[\+\-\*\/]?=')
    vars_a = {m.group(1) for m in write_re.finditer(body_a)
              if not m.group(1)[0].isupper()}  # skip constants
    vars_b = {m.group(1) for m in write_re.finditer(body_b)
              if not m.group(1)[0].isupper()}
    return list(vars_a & vars_b)


def _has_partial_op(body: str, var: str) -> bool:
    """Check if body partially modifies var (e.g. var -= Math.min(...))."""
    partial_re = re.compile(
        rf'\b{re.escape(var)}\b\s*-=\s*(?:Math\.min|min)\s*\('
        rf'|\bMath\.min\s*\([^)]*\b{re.escape(var)}\b',
        re.IGNORECASE,
    )
    return bool(partial_re.search(body))


def _has_early_return_after_guard(body: str) -> bool:
    """Check if body has an if-guard followed by early return (all-or-nothing)."""
    return bool(re.search(
        r'if\s*\([^)]+\)\s*\{[^}]*return\s*;[^}]*\}',
        body, re.DOTALL,
    ))


def detect_sibling_asymmetry(src: str) -> List[InvariantFinding]:
    """
    Find function pairs where one does partial resource handling,
    the other does all-or-nothing. Classic example: infiniFi
    _handlePositiveYield (partial fill) vs _handleNegativeYield (all-or-nothing).
    """
    findings = []
    fns      = _extract_functions(src)

    # Group functions by their sibling root
    groups: Dict[str, Dict[str, Dict]] = {}
    for fn in fns:
        key = _fn_key(fn['name'])
        if key is None:
            continue
        root, side = key
        if root not in groups:
            groups[root] = {}
        groups[root][side] = fn

    for root, sides in groups.items():
        if len(sides) < 2:
            continue

        side_names = list(sides.keys())
        for i in range(len(side_names)):
            for j in range(i + 1, len(side_names)):
                fn_a = sides[side_names[i]]
                fn_b = sides[side_names[j]]

                shared = _shared_state_vars(
                    _strip_comments(fn_a['body']),
                    _strip_comments(fn_b['body']),
                )
                if not shared:
                    continue

                for var in shared:
                    a_partial = _has_partial_op(_strip_comments(fn_a['body']), var)
                    b_partial = _has_partial_op(_strip_comments(fn_b['body']), var)
                    a_cliff   = _has_early_return_after_guard(_strip_comments(fn_a['body']))
                    b_cliff   = _has_early_return_after_guard(_strip_comments(fn_b['body']))

                    # Asymmetry: one has partial, other is all-or-nothing
                    if a_partial and b_cliff and not b_partial:
                        asymmetric_fn = fn_b
                        correct_fn    = fn_a
                    elif b_partial and a_cliff and not a_partial:
                        asymmetric_fn = fn_a
                        correct_fn    = fn_b
                    else:
                        continue

                    findings.append(InvariantFinding(
                        severity=InvariantSeverity.HIGH,
                        detector='SIBLING_ASYMMETRY',
                        title=(
                            f"Asymmetric `{var}` handling: "
                            f"`{correct_fn['name']}` partial vs "
                            f"`{asymmetric_fn['name']}` all-or-nothing"
                        ),
                        description=(
                            f"`{correct_fn['name']}()` partially modifies `{var}` "
                            f"(correct behavior). Its sibling `{asymmetric_fn['name']}()` "
                            f"handles `{var}` all-or-nothing — either fully consumed or "
                            f"entirely skipped. This asymmetry breaks the economic "
                            f"invariant: both paths should consume `{var}` proportionally."
                        ),
                        location=f"{asymmetric_fn['name']}():L{asymmetric_fn['line']}",
                        confidence=0.75,
                        fix=(
                            f"In `{asymmetric_fn['name']}()`, replace the all-or-nothing "
                            f"guard with partial consumption mirroring `{correct_fn['name']}()`."
                        ),
                    ))

    return findings


# ---------------------------------------------------------------------------
# Detector 3: Orphaned Resource
#
# A state variable (buffer, reserve, bail-out fund) exists and has a
# non-zero value in one code path but is completely bypassed in another.
# ---------------------------------------------------------------------------

_BALANCE_READ_RE  = re.compile(r'\bbalanceOf\s*\(|\.balance\b|\b(\w+[Bb]uffer|reserve\w*|bail\w*)\b')
_BALANCE_WRITE_RE = re.compile(r'\b(\w+[Bb]uffer|reserve\w*)\s*[\+\-]?=')

def detect_orphaned_resource(src: str) -> List[InvariantFinding]:
    """
    Find: function reads a buffer/reserve variable to check if it exists,
    but in the else/fallthrough branch does NOT consume or update it.
    The resource sits orphaned — checked but not used.
    """
    findings = []
    fns      = _extract_functions(src)

    for fn in fns:
        body  = _strip_comments(fn['body'])

        # Find assignments like: uint256 safetyBuffer = X.balanceOf(...)
        resource_assign = re.search(
            r'\buint(?:256|128|64)?\s+(\w*[Bb]uffer\w*|\w*[Rr]eserve\w*|\w*[Bb]ailout\w*)\s*=',
            body,
        )
        if not resource_assign:
            continue

        resource_var = resource_assign.group(1)

        # Find if-guard using this variable
        guard = re.search(
            rf'if\s*\([^)]*\b{re.escape(resource_var)}\b[^)]*\)\s*\{{',
            body,
        )
        if not guard:
            continue

        # Check the if-body for consume operations
        if_body = _extract_body(body, guard.end() - 1)
        if not _CONSUME_ALL_RE.search(if_body):
            continue
        if 'return' not in if_body:
            continue

        # Check AFTER the if-block: is resource_var consumed?
        after_pos = body.find(if_body) + len(if_body) + 1
        after_body = body[after_pos:]

        consumed_after = bool(re.search(
            rf'\b(?:burn|reduce|applyLoss|deduct|subtract|consume)\s*\([^)]*\b{re.escape(resource_var)}\b',
            after_body, re.IGNORECASE,
        ))
        reduced_loss = bool(re.search(
            rf'\w+\s*-=\s*{re.escape(resource_var)}\b',
            after_body,
        ))

        if not consumed_after and not reduced_loss:
            findings.append(InvariantFinding(
                severity=InvariantSeverity.HIGH,
                detector='ORPHANED_RESOURCE',
                title=f"Orphaned `{resource_var}` in `{fn['name']}()`: read but not consumed in fallthrough",
                description=(
                    f"`{fn['name']}()` reads `{resource_var}` and correctly consumes it "
                    f"when sufficient. In the fallthrough path (when insufficient), "
                    f"`{resource_var}` is never consumed or reduced — it sits orphaned "
                    f"in the contract while the full loss passes to the next layer."
                ),
                location=f"{fn['name']}():L{fn['line']}",
                confidence=0.85,
                fix=(
                    f"Before the fallthrough logic:\n"
                    f"  if ({resource_var} > 0) {{ burn({resource_var}); loss -= {resource_var}; }}"
                ),
                poc=(
                    f"// Verify orphan:\n"
                    f"// 1. Set {resource_var} = X (non-zero but < loss)\n"
                    f"// 2. Call {fn['name']}(loss > X)\n"
                    f"// 3. Assert: {resource_var} unchanged after call → ORPHANED"
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Detector 4: Threshold Cliff
#
# Find >= / <= comparisons where a tiny difference in input causes
# discontinuous (cliff) output behavior.
# ---------------------------------------------------------------------------

def detect_threshold_cliff(src: str) -> List[InvariantFinding]:
    """
    Find: if (A >= B) { big_consequence_A; } else { big_consequence_B; }
    where big_consequence_A and big_consequence_B are very different in magnitude.

    Classic example: fee tier switches, penalty thresholds, liquidation triggers.
    """
    findings = []
    fns      = _extract_functions(src)

    # Patterns that suggest "big consequence" (fund movement, loss application)
    _BIG_CONSEQUENCE_RE = re.compile(
        r'\b(?:applyLoss|liquidate|slash|penalt|seize|confiscate|wipe|drain'
        r'|fullLoss|totalLoss|sweep|emergencyWithdraw)\b',
        re.IGNORECASE,
    )

    _THRESHOLD_GUARD_RE = re.compile(
        r'if\s*\([^)]*(?:>=|<=|==)[^)]*\)',
        re.MULTILINE,
    )

    for fn in fns:
        body = _strip_comments(fn['body'])

        for guard in _THRESHOLD_GUARD_RE.finditer(body):
            if_body   = _extract_body(body, guard.end())
            after_pos = body.find(if_body) + len(if_body) + 1
            else_body = body[after_pos:after_pos + 300]  # scan ~300 chars after

            in_if    = bool(_BIG_CONSEQUENCE_RE.search(if_body))
            in_else  = bool(_BIG_CONSEQUENCE_RE.search(else_body))

            # Only flag if consequence in one branch but not both (asymmetric)
            if in_if and not in_else:
                findings.append(InvariantFinding(
                    severity=InvariantSeverity.MEDIUM,
                    detector='THRESHOLD_CLIFF',
                    title=f"Threshold cliff in `{fn['name']}()`: discontinuous consequence",
                    description=(
                        f"`{fn['name']}()` has a `>=`/`<=` guard that triggers a "
                        f"high-consequence operation (loss/liquidation/slash) only "
                        f"in one branch. A 1-unit difference at the boundary causes "
                        f"drastically different outcomes for users near the threshold."
                    ),
                    location=f"{fn['name']}():L{fn['line']}",
                    confidence=0.60,
                    fix="Consider graduated consequences near the boundary (linear interpolation or grace zone).",
                ))

    return findings


# ---------------------------------------------------------------------------
# Detector 5: Accounting Gap
#
# In a function that handles token flows, verify:
#   tokens_in == tokens_out + tokens_stored
# Flag branches where this invariant may be violated.
# ---------------------------------------------------------------------------

_TOKEN_IN_RE  = re.compile(
    r'\b(?:safeTransferFrom|transferFrom|deposit|receive|mint)\s*\([^)]*,\s*(\w+)\)',
    re.IGNORECASE,
)
_TOKEN_OUT_RE = re.compile(
    r'\b(?:safeTransfer|transfer|withdraw|send|burn)\s*\([^)]*,\s*(\w+)\)',
    re.IGNORECASE,
)

def detect_accounting_gap(src: str) -> List[InvariantFinding]:
    """
    Find functions where token inflow amount variables don't appear
    in any outflow or storage path — tokens enter and disappear.
    """
    findings = []
    fns      = _extract_functions(src)

    for fn in fns:
        body = _strip_comments(fn['body'])

        inflows  = [m.group(1) for m in _TOKEN_IN_RE.finditer(body)]
        outflows = [m.group(1) for m in _TOKEN_OUT_RE.finditer(body)]

        if not inflows:
            continue

        # Check each inflow variable appears somewhere in outflow or state write
        for var in inflows:
            if var in outflows:
                continue
            # Check if var is stored to state
            stored = bool(re.search(
                rf'\b\w+\b\s*[\+\-]?=\s*[^;]*\b{re.escape(var)}\b',
                body,
            ))
            if not stored:
                findings.append(InvariantFinding(
                    severity=InvariantSeverity.MEDIUM,
                    detector='ACCOUNTING_GAP',
                    title=f"Accounting gap in `{fn['name']}()`: `{var}` received but not tracked",
                    description=(
                        f"`{fn['name']}()` receives `{var}` tokens (via transfer/deposit/mint) "
                        f"but `{var}` does not appear in any outflow or state storage path. "
                        f"Tokens may be silently lost or double-counted."
                    ),
                    location=f"{fn['name']}():L{fn['line']}",
                    confidence=0.55,
                    fix=f"Ensure `{var}` is either transferred out, burned, or credited to a state variable.",
                ))

    return findings


# ---------------------------------------------------------------------------
# Detector 6: Fee Rounding Bias
#
# When protocol and user each get a share of a value, both rounded DOWN,
# the user is systematically undercharged. When one rounds down and the
# other computes residual (total - fee), rounding always favors the protocol.
# Classic bug class in fee-split and reward-split functions.
# ---------------------------------------------------------------------------

_FEE_SPLIT_RE = re.compile(
    r'\b(\w+[Ff]ee\w*|\w+[Pp]rotocol\w*|\w+[Tt]reasury\w*)\s*=\s*[^;]+\s*/',
    re.MULTILINE,
)
_USER_SHARE_RE = re.compile(
    r'\b(\w+[Uu]ser\w*|\w+[Rr]eward\w*|\w+[Aa]mount\w*)\s*=\s*[^;]*-\s*\w+[Ff]ee\w*',
    re.MULTILINE,
)

def detect_fee_rounding_bias(src: str) -> List[InvariantFinding]:
    """
    Find: protocolFee = total * bps / 10000;
          userAmount  = total * (10000 - bps) / 10000;  // rounds separately → dust loss

    The correct pattern: fee = ...; user = total - fee;
    Both dividing independently causes 1-2 wei systematic drift per tx.
    Over millions of txs on high-volume protocols this becomes material.
    """
    findings = []
    fns = _extract_functions(src)

    for fn in fns:
        body = _strip_comments(fn['body'])

        fee_splits  = list(_FEE_SPLIT_RE.finditer(body))
        user_shares = list(_USER_SHARE_RE.finditer(body))

        if not fee_splits:
            continue

        for fee_m in fee_splits:
            fee_var = fee_m.group(1)

            # Check if user share is computed as (total - fee_var) — correct
            # Or computed independently via another division — biased
            user_residual = bool(re.search(
                rf'\w+\s*=\s*[^;]*-\s*{re.escape(fee_var)}\b', body
            ))
            user_independent_div = bool(re.search(
                rf'\w+\s*=\s*[^;]*/\s*\w+[^;]*[;\n]', body[fee_m.end():][:400]
            ))

            if not user_residual and user_independent_div:
                findings.append(InvariantFinding(
                    severity=InvariantSeverity.LOW,
                    detector='FEE_ROUNDING_BIAS',
                    title=f"Fee rounding bias in `{fn['name']}()`: both shares divided independently",
                    description=(
                        f"`{fn['name']}()` computes `{fee_var}` via division and then computes "
                        f"the user share via a separate division. Integer division truncates twice, "
                        f"causing 1-2 wei systematic loss per transaction. On high-volume protocols "
                        f"this accumulates into material protocol advantage."
                    ),
                    location=f"{fn['name']}():L{fn['line']}",
                    confidence=0.65,
                    fix=f"Compute user share as `userAmount = total - {fee_var}` to avoid double truncation.",
                    poc=(
                        f"// Bias demo:\n"
                        f"// total=100, bps=333 → fee=33, user=66 (loses 1 wei)\n"
                        f"// Correct: fee=33, user=total-fee=67 (exact)"
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Detector 7: Reward Cliff (epoch boundary discontinuity)
#
# Reward functions that use block.timestamp with epoch division create
# cliff behavior: adding 1 second can change epoch and jump rewards.
# ---------------------------------------------------------------------------

_EPOCH_RE = re.compile(
    r'\bblock\.timestamp\s*/\s*(\w+|\d+)',
    re.MULTILINE,
)
_REWARD_FN_RE = re.compile(
    r'\b(?:reward|emission|distribute|accrue|earn)\b',
    re.IGNORECASE,
)

def detect_reward_cliff(src: str) -> List[InvariantFinding]:
    """
    Find: epoch = block.timestamp / EPOCH_DURATION; reward = ... * epoch;

    A 1-second difference at an epoch boundary can change the epoch count,
    causing discontinuous reward jumps. Attacker can grief by timing calls
    to straddle epoch boundaries.
    """
    findings = []
    fns = _extract_functions(src)

    for fn in fns:
        body = _strip_comments(fn['body'])

        if not _REWARD_FN_RE.search(fn['name'] + ' ' + body):
            continue

        epoch_uses = list(_EPOCH_RE.finditer(body))
        if not epoch_uses:
            continue

        # Check if epoch value is used in reward arithmetic
        for epoch_m in epoch_uses:
            divisor = epoch_m.group(1)
            after   = body[epoch_m.end():][:600]

            # Look for the epoch variable being used in multiplication or addition
            epoch_var_assign = re.search(
                r'\b(\w+)\s*=\s*block\.timestamp\s*/\s*' + re.escape(divisor),
                body,
            )
            if not epoch_var_assign:
                continue

            epoch_var = epoch_var_assign.group(1)
            used_in_reward = bool(re.search(
                rf'\b{re.escape(epoch_var)}\b\s*[\*\+]|\*\s*{re.escape(epoch_var)}\b',
                after,
            ))

            if used_in_reward:
                findings.append(InvariantFinding(
                    severity=InvariantSeverity.MEDIUM,
                    detector='REWARD_CLIFF',
                    title=f"Epoch boundary cliff in `{fn['name']}()`: reward jumps at `block.timestamp / {divisor}`",
                    description=(
                        f"`{fn['name']}()` computes epoch as `block.timestamp / {divisor}` and uses "
                        f"it directly in reward calculation. A 1-second difference at an epoch boundary "
                        f"causes a discontinuous reward jump. Users can be griefed or front-run near "
                        f"epoch transitions."
                    ),
                    location=f"{fn['name']}():L{fn['line']}",
                    confidence=0.70,
                    fix=(
                        "Use a continuous reward rate (reward per second) rather than epoch-based jumps. "
                        "If epochs are required, checkpoint rewards at the epoch boundary, not the call time."
                    ),
                    poc=(
                        f"// Cliff demo:\n"
                        f"// block.timestamp = EPOCH_DURATION * N - 1 → epoch = N-1\n"
                        f"// block.timestamp = EPOCH_DURATION * N     → epoch = N\n"
                        f"// 1 second difference → full extra epoch reward"
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Detector 8: Griefable Accounting Updater
#
# State update depends on an external call's return value. An attacker who
# controls the external contract can force reverts or return zero, preventing
# accounting updates while keeping the function callable (griefing without DoS).
# ---------------------------------------------------------------------------

_EXT_CALL_RESULT_RE = re.compile(
    r'\(bool\s+\w+,\s*(?:bytes\s+\w+)?\)\s*=\s*\w+\.call|'
    r'\bI\w+\([^)]*\)\.\w+\s*\([^)]*\)\s*;',
    re.MULTILINE,
)

def detect_griefable_updater(src: str) -> List[InvariantFinding]:
    """
    Find: uint256 newState = externalContract.getValue();
          state = newState;  // if externalContract reverts → state never updates

    If an attacker controls externalContract, they can prevent state updates
    while leaving the function callable (griefing, not bricking).
    """
    findings = []
    fns = _extract_functions(src)

    for fn in fns:
        body = _strip_comments(fn['body'])

        # Find external calls that assign their result to a local var
        ext_assigns = list(re.finditer(
            r'\b(?:uint\d*|int\d*|bool|address|bytes\d*)\s+(\w+)\s*=\s*'
            r'I\w+\([^)]*\)\.\w+\s*\(',
            body,
        ))
        if not ext_assigns:
            continue

        for assign in ext_assigns:
            local_var = assign.group(1)
            after = body[assign.end():][:400]

            # Check: local_var is then written to a storage state var
            stored = bool(re.search(
                rf'\b\w+\b\s*=\s*[^;]*\b{re.escape(local_var)}\b',
                after,
            ))
            # And there's no try/catch around the external call
            has_try = 'try ' in body[:assign.start()][-200:] or 'try ' in after[:200]

            if stored and not has_try:
                findings.append(InvariantFinding(
                    severity=InvariantSeverity.LOW,
                    detector='GRIEFABLE_UPDATER',
                    title=f"Griefable state update in `{fn['name']}()` via unchecked external call",
                    description=(
                        f"`{fn['name']}()` reads `{local_var}` from an external call and stores it "
                        f"to state without a try/catch. If the external contract is attacker-controlled "
                        f"or upgradeable, it can prevent state updates by reverting — griefing users "
                        f"who depend on fresh state without causing a full DoS."
                    ),
                    location=f"{fn['name']}():L{fn['line']}",
                    confidence=0.60,
                    fix=(
                        "Wrap the external call in try/catch. On failure, use stale state or emit an event "
                        "rather than reverting — this prevents griefing while maintaining liveness."
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

class InvariantFuzzer:
    """
    Run all novel invariant detectors on Solidity source.
    Designed to complement Slither (static CFG) with economic behavior analysis.
    """

    DETECTORS = [
        ('waterfall_cliff',    detect_waterfall_cliff),
        ('sibling_asymmetry',  detect_sibling_asymmetry),
        ('orphaned_resource',  detect_orphaned_resource),
        ('threshold_cliff',    detect_threshold_cliff),
        ('accounting_gap',     detect_accounting_gap),
        ('fee_rounding_bias',  detect_fee_rounding_bias),
        ('reward_cliff',       detect_reward_cliff),
        ('griefable_updater',  detect_griefable_updater),
    ]

    def analyze(self, source: str) -> List[InvariantFinding]:
        all_findings: List[InvariantFinding] = []
        for name, detector in self.DETECTORS:
            try:
                found = detector(source)
                all_findings.extend(found)
            except Exception:
                pass  # never crash the pipeline
        # Sort by severity
        _order = {
            InvariantSeverity.CRITICAL: 0,
            InvariantSeverity.HIGH:     1,
            InvariantSeverity.MEDIUM:   2,
            InvariantSeverity.LOW:      3,
            InvariantSeverity.INFO:     4,
        }
        all_findings.sort(key=lambda f: _order[f.severity])
        return all_findings

    def report(self, source: str) -> str:
        findings = self.analyze(source)
        if not findings:
            return "InvariantFuzzer: No findings.\n"
        lines = [f"InvariantFuzzer: {len(findings)} finding(s)\n"]
        for f in findings:
            lines.append(
                f"  [{f.severity.value}] [{f.confidence:.0%}] {f.title}\n"
                f"    Detector : {f.detector}\n"
                f"    Location : {f.location}\n"
                f"    Desc     : {f.description[:200]}...\n"
                + (f"    Fix      : {f.fix[:150]}\n" if f.fix else "")
                + (f"    PoC      : {f.poc[:200]}\n" if f.poc else "")
            )
        return '\n'.join(lines)
