"""
ChainEDR Commercial Detectors — 6 novel vulnerability classes.
These are NOT in the open-source version.

Classes added:
  1. UNSAFE_DOWNCAST          — uint256→uintN silent truncation → phantom tokens
  2. PERMIT_FRONTRUN_DOS      — permit() griefing blocks user operations
  3. PUSH_PAYMENT_DOS         — push-to-arbitrary-addr blocks batch distributions
  4. REBASING_IN_4626         — rebasing token as ERC4626 asset → share price drift
  5. INFINITE_PERMIT          — missing deadline on EIP-2612 permit → eternal signature
  6. PROXY_STORAGE_COLLISION  — implementation var at proxy admin slot → hijack
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class CommercialFinding:
    title: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    location: str
    cwe: str
    exploitable: bool
    confidence: float      # 0.0–1.0
    fix: str
    novel: bool = True     # always True for commercial detectors


# ---------------------------------------------------------------------------
# 1. UNSAFE DOWNCAST — uint256 → uintN without bounds check
# ---------------------------------------------------------------------------
# Pattern: uint128 x = uint128(y) where y is uint256 from external/calculated
# Risk: if y > 2^N, truncation silently creates wrong value
# Real bugs: Compound III bad debt (2022), Notional Finance (2022)

_DOWNCAST_RE = re.compile(
    r'uint(\d+)\s*\(\s*(\w+)\s*\)',
    re.MULTILINE
)
_RISKY_SOURCES_RE = re.compile(
    r'(balanceOf|totalSupply|getReserves|price|amount|value|balance|shares|assets'
    r'|fee|reward|pending|owed|debt|collateral)',
    re.IGNORECASE
)


def detect_unsafe_downcast(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings = []
    lines = source.splitlines()

    for i, line in enumerate(lines):
        m = _DOWNCAST_RE.search(line)
        if not m:
            continue
        target_bits = int(m.group(1))
        var_name = m.group(2)
        if target_bits >= 256:
            continue
        if not _RISKY_SOURCES_RE.search(var_name):
            continue
        # Check if SafeCast is used nearby
        if 'SafeCast' in line or 'toUint' in line:
            continue
        fn_name = _enclosing_function(lines, i)
        findings.append(CommercialFinding(
            title=f"Unsafe downcast to uint{target_bits} in {fn_name}()",
            description=(
                f"`uint{target_bits}({var_name})` silently truncates if `{var_name}` "
                f"exceeds 2^{target_bits}-1. For DeFi values (balances, prices, shares) "
                f"truncation creates phantom tokens or zeroed balances that break accounting. "
                f"Real precedent: Compound III $150k bad debt (2022)."
            ),
            severity="HIGH",
            category="UNSAFE_DOWNCAST",
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-197",
            exploitable=True,
            confidence=0.78,
            fix=f"Use `SafeCast.toUint{target_bits}({var_name})` which reverts on overflow.",
        ))
    return findings


# ---------------------------------------------------------------------------
# 2. PERMIT FRONT-RUN DoS — permit() used without absorbing InvalidSignature
# ---------------------------------------------------------------------------
# Pattern: contract calls permit() then acts on it, but if attacker front-runs
# with the same permit, victim's permit() reverts → whole tx fails
# Real bugs: EIP-2612 griefing on Uniswap v2 routers, countless DEX aggregators

_PERMIT_CALL_RE = re.compile(
    r'\.permit\s*\(',
    re.MULTILINE
)
_TRY_PERMIT_RE = re.compile(
    r'try\s+\w+\.permit\s*\(',
    re.MULTILINE
)


def detect_permit_frontrun_dos(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings = []
    lines = source.splitlines()
    seen_fns = set()

    for i, line in enumerate(lines):
        if not _PERMIT_CALL_RE.search(line):
            continue
        # Skip if already wrapped in try
        context = '\n'.join(lines[max(0, i-2):i+3])
        if _TRY_PERMIT_RE.search(context):
            continue
        if 'try' in context and 'permit' in context:
            continue
        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)
        findings.append(CommercialFinding(
            title=f"Permit front-run DoS in {fn_name}()",
            description=(
                f"`{fn_name}()` calls `.permit()` without try/catch. An attacker can front-run "
                f"with the same (v, r, s) signature to consume the permit first. The victim's "
                f"`.permit()` then reverts with `InvalidSignature`, blocking the entire "
                f"operation. Affected protocols: Uniswap V2 router, many aggregators."
            ),
            severity="MEDIUM",
            category="PERMIT_FRONTRUN_DOS",
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-703",
            exploitable=True,
            confidence=0.82,
            fix=(
                "Wrap permit() in try/catch:\n"
                "```solidity\n"
                "try token.permit(owner, spender, amount, deadline, v, r, s) {} catch {}\n"
                "// Then proceed — if permit was already consumed, allowance may still be set\n"
                "```"
            ),
        ))
    return findings


# ---------------------------------------------------------------------------
# 3. PUSH PAYMENT DoS — transferring ETH/ERC20 to untrusted address in a loop
# ---------------------------------------------------------------------------
# Pattern: loop over users/winners with external .transfer() or .call{value:}()
# Risk: one failing recipient (malicious contract) blocks all others
# Real bugs: King of Ether ($1M locked), various airdrop contracts

_LOOP_RE = re.compile(
    r'\b(for|while)\b.*\{',
    re.MULTILINE
)
_PUSH_PAY_RE = re.compile(
    r'(\.transfer\s*\(|\.send\s*\(|\.call\s*\{[^}]*value[^}]*\}\s*\()',
    re.MULTILINE
)


def detect_push_payment_dos(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings = []
    lines = source.splitlines()
    seen_fns = set()

    for i, line in enumerate(lines):
        if not _LOOP_RE.search(line):
            continue
        # Look ahead for push payment within ~15 lines of loop opening
        block = '\n'.join(lines[i:i+20])
        if not _PUSH_PAY_RE.search(block):
            continue
        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)

        # Check if there's try/catch protection
        if 'try' in block and ('call' in block or 'transfer' in block):
            continue

        findings.append(CommercialFinding(
            title=f"Push-over-pull DoS in {fn_name}(): loop with external transfer",
            description=(
                f"`{fn_name}()` pushes ETH/tokens to addresses inside a loop. "
                f"If one recipient is a contract that reverts on receive, the entire "
                f"distribution is blocked permanently. The attacker can deploy a reverting "
                f"receiver to grief all other recipients. Use pull-payment pattern instead."
            ),
            severity="MEDIUM",
            category="PUSH_PAYMENT_DOS",
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-400",
            exploitable=True,
            confidence=0.75,
            fix=(
                "Replace push with pull: store claimable balances in a mapping, "
                "let users call `claim()` individually. Or wrap each transfer in "
                "try/catch and continue on failure."
            ),
        ))
    return findings


# ---------------------------------------------------------------------------
# 4. REBASING TOKEN IN ERC4626 — share price drift without accounting
# ---------------------------------------------------------------------------
# Pattern: ERC4626 vault that takes stETH/OUSD/rETH without special handling
# Risk: rebase increases/decreases totalAssets() without deposit/withdraw events
#       → share price drifts, violates ERC4626 rounding invariant
# Real bugs: multiple ERC4626 wrappers for stETH

_REBASING_TOKENS = re.compile(
    r'\b(stETH|wstETH|rETH|cbETH|OUSD|OETH|aToken|aUSDC|rebase|RebasingERC20)',
    re.IGNORECASE
)
_ERC4626_SIGNALS = re.compile(
    r'\b(ERC4626|IERC4626|totalAssets|convertToShares|convertToAssets|previewDeposit)',
    re.IGNORECASE
)


def detect_rebasing_in_4626(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings = []

    has_4626 = bool(_ERC4626_SIGNALS.search(source))
    has_rebasing = bool(_REBASING_TOKENS.search(source))

    if not (has_4626 and has_rebasing):
        return findings

    # Check if totalAssets() accounts for rebasing (reads balance dynamically)
    total_assets_fn = re.search(
        r'function\s+totalAssets\s*\([^)]*\)[^{]*\{([^}]{0,300})\}',
        source, re.DOTALL
    )
    if total_assets_fn:
        body = total_assets_fn.group(1)
        if 'balanceOf' in body or 'getPooledEthByShares' in body:
            return findings  # has proper accounting

    token_match = _REBASING_TOKENS.search(source)
    token_name = token_match.group(0) if token_match else "rebasing token"

    findings.append(CommercialFinding(
        title=f"Rebasing token ({token_name}) in ERC4626 vault — share price drift",
        description=(
            f"This ERC4626 vault uses `{token_name}`, a rebasing token, as its underlying. "
            f"Rebases change `balanceOf()` without triggering deposits/withdrawals, so "
            f"`totalAssets()` drifts silently. Early depositors gain at the expense of "
            f"later depositors, violating ERC4626 rounding invariants. "
            f"Impact: protocol insolvency if negative rebase (slashing)."
        ),
        severity="HIGH",
        category="REBASING_IN_4626",
        location="totalAssets()",
        cwe="CWE-682",
        exploitable=True,
        confidence=0.80,
        fix=(
            "Use the non-rebasing wrapper (wstETH instead of stETH, rETH is already non-rebasing). "
            "Or override totalAssets() to dynamically query the underlying balance: "
            "`return IERC20(asset()).balanceOf(address(this));`"
        ),
    ))
    return findings


# ---------------------------------------------------------------------------
# 5. INFINITE PERMIT — EIP-2612 permit with deadline=type(uint256).max
# ---------------------------------------------------------------------------
# Pattern: hardcoded max deadline in permit call means signature valid forever
# Risk: stolen/leaked key = permanent drain authorization
# Real bugs: early Compound governance, multiple DEX routers

_PERMIT_MAX_RE = re.compile(
    r'\.permit\b.*?type\s*\(\s*uint256\s*\)\s*\.\s*max',
    re.MULTILINE | re.DOTALL
)
_PERMIT_HARDCODED_RE = re.compile(
    r'\.permit\b.*?,\s*(\d{15,})\s*[,;)]',
    re.MULTILINE
)


def detect_infinite_permit(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings = []
    lines = source.splitlines()

    for i, line in enumerate(lines):
        full_context = '\n'.join(lines[max(0, i-1):i+5])
        if _PERMIT_MAX_RE.search(full_context) or _PERMIT_HARDCODED_RE.search(full_context):
            fn_name = _enclosing_function(lines, i)
            findings.append(CommercialFinding(
                title=f"Infinite-deadline permit in {fn_name}()",
                description=(
                    f"`{fn_name}()` calls permit with `deadline = type(uint256).max` (or a "
                    f"hardcoded far-future timestamp). A leaked private key gives an attacker "
                    f"a permanent signature that never expires — they can drain the approved "
                    f"amount at any point in the future, even years after the original user "
                    f"forgot about the approval."
                ),
                severity="MEDIUM",
                category="INFINITE_PERMIT",
                location=f"{fn_name}():L{i+1}",
                cwe="CWE-613",
                exploitable=False,
                confidence=0.85,
                fix=(
                    "Use `block.timestamp + 30 minutes` as deadline. "
                    "Let the user provide the deadline from off-chain (UI sets it). "
                    "Never hardcode `type(uint256).max`."
                ),
            ))
            break  # one finding per contract
    return findings


# ---------------------------------------------------------------------------
# 6. PROXY STORAGE COLLISION — implementation var overlaps EIP-1967 slots
# ---------------------------------------------------------------------------
# Pattern: contract uses slot 0 for state variable + is also a proxy
# The first storage slot may collide with the proxy admin/implementation slot
# if not using EIP-1967 randomized slots
# Real bugs: Audius hack ($6M, 2022) — storage collision on proxy upgrade

_EIP1967_SLOTS = {
    # EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin":          "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon":         "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}

_PROXY_SIGNALS = re.compile(
    r'\b(delegatecall|Proxy|UUPS|TransparentUpgradeableProxy|upgradeable|_implementation)\b',
    re.IGNORECASE
)
_SLOT0_VAR_RE = re.compile(
    r'^\s*(address|uint256|bool|bytes32|mapping)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;',
    re.MULTILINE
)
_SLOT_ANNOTATION_RE = re.compile(
    r'(StorageSlot|_IMPLEMENTATION_SLOT|eip1967|assembly.*slot)',
    re.IGNORECASE
)


def detect_proxy_storage_collision(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings = []

    if not _PROXY_SIGNALS.search(source):
        return findings

    # Check if using EIP-1967 style storage (safe)
    if _SLOT_ANNOTATION_RE.search(source):
        return findings

    # Count state variables at top-level (approximate slot 0 usage)
    vars_at_top = _SLOT0_VAR_RE.findall(source)
    if not vars_at_top:
        return findings

    # Count how many contracts are in the file
    contract_count = len(re.findall(r'\bcontract\s+\w+', source))
    if contract_count < 2:
        return findings  # need both proxy + implementation in scope

    first_var_type, first_var_name = vars_at_top[0]

    findings.append(CommercialFinding(
        title=f"Proxy storage collision risk: `{first_var_name}` at slot 0",
        description=(
            f"This file contains proxy patterns but the implementation contract uses "
            f"`{first_var_type} {first_var_name}` at storage slot 0 (or near it). "
            f"If the proxy admin/implementation address is stored at slot 0 via an older "
            f"non-EIP-1967 pattern, an upgrade can overwrite it with `{first_var_name}`, "
            f"enabling an attacker to hijack the implementation pointer. "
            f"Real precedent: Audius $6M hack (2022)."
        ),
        severity="HIGH",
        category="PROXY_STORAGE_COLLISION",
        location=f"{first_var_name} (slot 0)",
        cwe="CWE-119",
        exploitable=True,
        confidence=0.65,
        fix=(
            "Use EIP-1967 randomized storage slots for all proxy variables. "
            "Inherit from OpenZeppelin's `EIP1967Upgrade` or use `StorageSlot` library. "
            "Run `slither --detect uninitialized-local` + storage layout diff on upgrade."
        ),
    ))
    return findings


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _enclosing_function(lines: List[str], line_idx: int) -> str:
    fn_re = re.compile(r'^\s*function\s+(\w+)\s*\(')
    for i in range(line_idx, -1, -1):
        m = fn_re.match(lines[i])
        if m:
            return m.group(1)
    return "unknown"


# ---------------------------------------------------------------------------
# Main entry point — called from static_analyzer run()
# ---------------------------------------------------------------------------

def run_commercial_detectors(source: str, functions: List[Dict]) -> List[CommercialFinding]:
    findings: List[CommercialFinding] = []
    findings.extend(detect_unsafe_downcast(source, functions))
    findings.extend(detect_permit_frontrun_dos(source, functions))
    findings.extend(detect_push_payment_dos(source, functions))
    findings.extend(detect_rebasing_in_4626(source, functions))
    findings.extend(detect_infinite_permit(source, functions))
    findings.extend(detect_proxy_storage_collision(source, functions))
    return findings
