"""
ChainEDR MEV Protection & ERC-6900 Modular Account Checker

Two new detector modules:

MEV_PROTECTION — Detects contracts missing critical MEV sandwich defenses:
  MEV-001  SWAP_NO_SLIPPAGE_PROTECTION   — swap without minAmountOut/maxAmountIn
  MEV-002  COMMIT_REVEAL_MISSING         — on-chain randomness without commit-reveal
  MEV-003  BACKRUNNABLE_LIQUIDATION      — liquidation with no priority fee enforcement
  MEV-004  UNPROTECTED_PRICE_RANGE       — Uniswap V3 mint with minAmount0/1 = 0

ERC6900_SECURITY — Security checks for ERC-6900 (Modular Account Standard) contracts:
  ERC6900-001  MISSING_HOOK_VALIDATION         — install hook without capability check
  ERC6900-002  HOOK_DEPENDENCY_LOOP            — hooks can call back into account
  ERC6900-003  UNGUARDED_MODULE_INSTALL        — installModule without EntryPoint gate
  ERC6900-004  EXECUTION_HOOK_BYPASS           — pre/post execution hook not enforced
  ERC6900-005  VALIDATION_HOOK_SKIP_FLAG       — validation hook SKIP flag missing
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List


# ─────────────────────────────────────────────────────────────────────────────
# Shared data class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GenericFinding:
    check_id: str
    title: str
    severity: str
    description: str
    location: str
    recommendation: str
    confidence: float


# =============================================================================
# MEV PROTECTION CHECKER
# =============================================================================

_SWAP_FUNC_RE = re.compile(
    r"function\s+(swap|exactInput|exactOutput|swapExactTokens|swapTokens"
    r"|addLiquidity|removeLiquidity|trade|exchange)\s*\(",
    re.IGNORECASE,
)
_MIN_AMOUNT_RE = re.compile(
    r"(minAmount|minOut|minReturn|amountOutMin|amountInMax|minReceived"
    r"|amountInMaximum|amountOutMinimum|minimum_amount|sqrtPriceLimitX96\s*!=\s*0"
    r"|\bmin[A-Z_]\w*|\bmax[A-Z_]\w*)",
    re.IGNORECASE,
)
_DEADLINE_RE = re.compile(
    r"(deadline\s*[><=!]|block\.timestamp\s*[<>]\s*deadline"
    r"|require.*deadline.*timestamp)",
    re.IGNORECASE,
)
_SLOT0_PRICE_RE = re.compile(
    r"(slot0\(\)|getReserves\(\)|currentPrice|sqrtPriceX96)\s*[^;]+;"
    r"[^\n]*\n[^\n]*(amount|price|value|out)\s*=",
    re.DOTALL,
)
_LIQUIDATION_RE = re.compile(
    r"function\s+(liquidate|liquidateBorrow|seize|forceLiquidation)\s*\(",
    re.IGNORECASE,
)
_PRIORITY_FEE_RE = re.compile(
    r"(tx\.gasprice|block\.basefee|maxPriorityFeePerGas|miner\.tip)",
    re.IGNORECASE,
)
_COMMIT_REVEAL_RE = re.compile(
    r"(commit|reveal|commitment|_commitHash)",
    re.IGNORECASE,
)
_RANDOM_SEED_RE = re.compile(
    r"(block\.timestamp.*random|block\.prevrandao.*keccak|blockhash.*random"
    r"|uint.*random.*block\.(number|timestamp))",
    re.IGNORECASE,
)
_V3_MINT_RE = re.compile(r"(mint|increaseLiquidity)\s*\(", re.IGNORECASE)
_AMOUNT01_ZERO_RE = re.compile(
    r"(amount0Min\s*:\s*0|amount1Min\s*:\s*0|amount0Desired.*0.*amount0Min.*0)",
    re.IGNORECASE,
)


def check_mev_protection(source: str) -> List[GenericFinding]:
    findings: List[GenericFinding] = []
    lines = source.splitlines()

    def enclosing_fn(idx):
        fn_re = re.compile(r"^\s*function\s+(\w+)\s*\(")
        for j in range(idx, -1, -1):
            m = fn_re.match(lines[j])
            if m:
                return m.group(1)
        return "unknown"

    # MEV-001: Swap without slippage protection
    for i, line in enumerate(lines):
        if _SWAP_FUNC_RE.search(line):
            body = "\n".join(lines[i:min(i+40, len(lines))])
            header_end = re.search(r"[{;]", body)
            if header_end and body[header_end.start()] == ";":
                continue
            if not _MIN_AMOUNT_RE.search(body):
                fn = enclosing_fn(i)
                findings.append(GenericFinding(
                    check_id="MEV-001",
                    title=f"Swap function `{fn}()` missing slippage protection",
                    severity="HIGH",
                    description=(
                        f"`{fn}()` performs a DEX swap without enforcing `minAmountOut` "
                        f"or `maxAmountIn`. MEV bots can sandwich-attack every call to "
                        f"this function, moving the price before the swap and back after, "
                        f"extracting value from users. The median sandwich loss is ~0.5% "
                        f"per trade; on $1M TVL this is ~$5K/day."
                    ),
                    location=f"{fn}():L{i+1}",
                    recommendation=(
                        "Add a `minAmountOut` parameter and `require(amountOut >= minAmountOut)`. "
                        "For Uniswap V3, also set `sqrtPriceLimitX96` to bound price impact."
                    ),
                    confidence=0.82,
                ))

    # MEV-002: On-chain randomness without commit-reveal
    if _RANDOM_SEED_RE.search(source) and not _COMMIT_REVEAL_RE.search(source):
        for i, line in enumerate(lines):
            if _RANDOM_SEED_RE.search(line):
                fn = enclosing_fn(i)
                findings.append(GenericFinding(
                    check_id="MEV-002",
                    title=f"On-chain randomness in `{fn}()` without commit-reveal",
                    severity="MEDIUM",
                    description=(
                        f"`{fn}()` uses block state (timestamp, prevrandao, blockhash) "
                        f"as randomness without commit-reveal. Validators can manipulate "
                        f"`prevrandao` (within 1/256 probability per slot), and anyone "
                        f"can delay tx submission to cherry-pick a favourable block hash."
                    ),
                    location=f"{fn}():L{i+1}",
                    recommendation=(
                        "Use Chainlink VRF v2+ for off-chain verifiable randomness. "
                        "Or implement commit-reveal: user commits hash(secret+salt) in "
                        "block N, reveals in block N+2 to prevent look-ahead."
                    ),
                    confidence=0.75,
                ))
                break

    # MEV-003: Liquidation without priority fee enforcement
    for i, line in enumerate(lines):
        if _LIQUIDATION_RE.search(line):
            body = "\n".join(lines[i:min(i+30, len(lines))])
            if not _PRIORITY_FEE_RE.search(body):
                fn = enclosing_fn(i)
                findings.append(GenericFinding(
                    check_id="MEV-003",
                    title=f"Liquidation `{fn}()` backrunnable — no priority fee enforcement",
                    severity="MEDIUM",
                    description=(
                        f"Liquidation function `{fn}()` has no check on `tx.gasprice` "
                        f"or priority fee. Searchers can backrun oracle price updates "
                        f"with high-gas bundles to claim all liquidation rewards, "
                        f"extracting value from protocol's own keepers/bots."
                    ),
                    location=f"{fn}():L{i+1}",
                    recommendation=(
                        "Add `require(tx.gasprice <= maxGasPrice)` to prevent gas wars, "
                        "or implement a Dutch auction for liquidation incentive "
                        "that grows over time to share rewards with patient searchers."
                    ),
                    confidence=0.65,
                ))

    # MEV-004: Uniswap V3 mint with amount0Min/amount1Min = 0
    if _V3_MINT_RE.search(source) and _AMOUNT01_ZERO_RE.search(source):
        findings.append(GenericFinding(
            check_id="MEV-004",
            title="Uniswap V3 liquidity add with minAmount0/1 = 0 — sandwich vulnerable",
            severity="HIGH",
            description=(
                "Uniswap V3 `mint()` or `increaseLiquidity()` call has "
                "`amount0Min: 0, amount1Min: 0`. This disables slippage protection "
                "entirely: an attacker can move the pool price arbitrarily before the "
                "liquidity addition, causing the LP to add heavily imbalanced liquidity "
                "at a manipulated ratio and immediately lose value."
            ),
            location="contract-level",
            recommendation=(
                "Calculate expected amounts off-chain and pass `amount0Min` and `amount1Min` "
                "as 95-99% of the expected amounts. Never hardcode 0."
            ),
            confidence=0.90,
        ))

    return findings


# =============================================================================
# ERC-6900 MODULAR ACCOUNT SECURITY CHECKER
# =============================================================================

_MODULE_INSTALL_RE = re.compile(
    r"function\s+(installModule|installPlugin|addModule|_installModule)\s*\(",
    re.IGNORECASE,
)
_HOOK_INSTALL_RE = re.compile(
    r"function\s+(installHook|addHook|_applyHook|setHook)\s*\(",
    re.IGNORECASE,
)
_CAPABILITY_CHECK_RE = re.compile(
    r"(supportsInterface|moduleMetadata|moduleType|validateInstall|ERC6900)",
    re.IGNORECASE,
)
_ENTRYPOINT_GATE_RE = re.compile(
    r"(msg\.sender\s*==\s*entryPoint|require.*entryPoint|_checkEntryPoint"
    r"|onlyEntryPoint|IEntryPoint)",
)
_HOOK_CALLBACK_RE = re.compile(
    r"(IModule.*\.onInstall|IExecutionHook.*\.preExecutionHook"
    r"|IValidationHook.*\.preUserOpValidation)",
    re.IGNORECASE,
)
_REENTRANCY_RE = re.compile(r"(nonReentrant|ReentrancyGuard|_reentrancyGuard)")
_SKIP_FLAG_RE = re.compile(
    r"(SKIP_RUNTIME_VALIDATION|PRE_VALIDATION_HOOK_SKIP|skipHook|_skipValidation)",
    re.IGNORECASE,
)


def check_erc6900(source: str) -> List[GenericFinding]:
    """Security checks for ERC-6900 modular smart account contracts."""
    if not (re.search(r"(IModularAccount|ERC6900|IModule|installModule)", source, re.I)):
        return []

    findings: List[GenericFinding] = []

    # ERC6900-001: Hook install without capability validation
    if _HOOK_INSTALL_RE.search(source) and not _CAPABILITY_CHECK_RE.search(source):
        findings.append(GenericFinding(
            check_id="ERC6900-001",
            title="ERC-6900 hook installed without interface/capability validation",
            severity="HIGH",
            description=(
                "Hook installation does not validate that the hook contract "
                "implements the required ERC-6900 interface (`supportsInterface`) "
                "or `moduleMetadata`. An incompatible or malicious hook silently "
                "becomes a required execution step, bricking the account or "
                "enabling privilege escalation via a hook that returns success "
                "without performing the required validation."
            ),
            location="installHook()",
            recommendation=(
                "Require `IModule(hook).supportsInterface(REQUIRED_INTERFACE_ID)` "
                "before installation. Use the ERC-165 registry or ERC-6900 "
                "`moduleMetadata()` to verify module type and capabilities."
            ),
            confidence=0.78,
        ))

    # ERC6900-002: Hook dependency loop / hook calls back into account
    if _HOOK_CALLBACK_RE.search(source) and not _REENTRANCY_RE.search(source):
        findings.append(GenericFinding(
            check_id="ERC6900-002",
            title="ERC-6900 execution hook calls external module without reentrancy guard",
            severity="HIGH",
            description=(
                "Pre/post execution hooks call external module contracts without "
                "a reentrancy guard. A malicious module can re-enter the account "
                "during hook execution, observing partially applied state "
                "(e.g., after pre-hook but before post-hook), enabling "
                "double-execution attacks or state corruption."
            ),
            location="hook-execution",
            recommendation=(
                "Add `nonReentrant` (or EIP-1153 `TSTORE` based lock) to "
                "all functions that invoke external hooks. "
                "Consider a 'no-reentry' flag per account that is checked "
                "at the start of every hook dispatch."
            ),
            confidence=0.75,
        ))

    # ERC6900-003: Module install without EntryPoint gate
    if _MODULE_INSTALL_RE.search(source) and not _ENTRYPOINT_GATE_RE.search(source):
        findings.append(GenericFinding(
            check_id="ERC6900-003",
            title="ERC-6900 installModule() accessible without EntryPoint authorization",
            severity="CRITICAL",
            description=(
                "Module installation (`installModule`) can be called without "
                "going through the EntryPoint's UserOperation flow. "
                "This bypasses the account's signature validation, allowing "
                "anyone to install arbitrary modules — equivalent to an "
                "unprotected `upgrade()` function. Severity is CRITICAL "
                "as module installation grants arbitrary execution power."
            ),
            location="installModule()",
            recommendation=(
                "Restrict `installModule` to `msg.sender == address(entryPoint()) "
                "|| msg.sender == address(this)`. Never expose module install "
                "as a public function callable directly without UserOperation flow."
            ),
            confidence=0.85,
        ))

    # ERC6900-004: Pre/post execution hooks not enforced
    pre_hook_re = re.compile(r"(preExecutionHook|_runPreExecutionHook|hookData)", re.I)
    post_hook_re = re.compile(r"(postExecutionHook|_runPostExecutionHook)", re.I)
    if pre_hook_re.search(source) and not post_hook_re.search(source):
        findings.append(GenericFinding(
            check_id="ERC6900-004",
            title="ERC-6900 pre-execution hook without corresponding post-execution hook",
            severity="MEDIUM",
            description=(
                "Contract implements `preExecutionHook` but not `postExecutionHook`. "
                "ERC-6900 requires that pre/post hooks are always paired: the pre-hook "
                "returns `hookData` that MUST be passed to the post-hook. "
                "Missing post-hook means the hook's cleanup/accounting never runs, "
                "potentially leaving the module in an inconsistent state."
            ),
            location="hook-pair",
            recommendation=(
                "Implement `postExecutionHook(bytes hookData)` for every "
                "`preExecutionHook` implementation. Store hook context in a "
                "transient variable and clean it up in the post-hook."
            ),
            confidence=0.72,
        ))

    # ERC6900-005: Validation hook skip flag missing
    if re.search(r"(ValidationHook|userOpValidation|_validateUserOp)", source, re.I):
        if not _SKIP_FLAG_RE.search(source):
            findings.append(GenericFinding(
                check_id="ERC6900-005",
                title="ERC-6900 validation hooks without SKIP_RUNTIME_VALIDATION flag handling",
                severity="MEDIUM",
                description=(
                    "Validation hook implementation does not check for or emit "
                    "`SKIP_RUNTIME_VALIDATION` flag in the `validationData` return. "
                    "Without this flag, the account will run both the hook-level AND "
                    "runtime validation, causing double-validation overhead and "
                    "potential failures if hook and runtime validators have conflicting state."
                ),
                location="validateUserOp()",
                recommendation=(
                    "Return `_SIG_VALIDATION_PASSED | SKIP_RUNTIME_VALIDATION` "
                    "when appropriate. Follow ERC-6900 spec §4.4 for "
                    "`validationData` bit-packing conventions."
                ),
                confidence=0.68,
            ))

    return findings
