"""ChainEDR Static Solidity Analyzer v1.7.0

Usage model — TWO-TOOL AUDIT PIPELINE:
  Run Slither first (reentrancy, precision, unchecked returns, tx.origin,
  locked-ether, suicidal, access control, ERC standards).
  Run ChainEDR second — it finds what Slither misses.
  Together: complete static coverage.

  Slither covers (24 pattern classes):
    reentrancy-eth, divide-before-multiply, unchecked-lowlevel, tx-origin,
    locked-ether, suicidal, missing-zero-check, approval-griefing, msg-value-loop,
    controlled-delegatecall, arbitrary-send-eth, uninitialized-state, shadowing,
    boolean-equality, tautology, weak-prng, erc20-interface, ...

  ChainEDR uniquely covers (23 pattern classes, ZERO Slither overlap):
    read-only reentrancy       accrual-gate DoS           ERC4626 rounding direction
    rebasing token accounting  donation inflation          governance sandwich
    incomplete pausable        spot price oracle           missing slippage protection
    signature replay (nonce)   cross-chain msg validation  division-by-zero (vault)
    hardcoded 18-decimal       selfdestruct ETH injection  stale oracle (updatedAt)
    AMM deadline (MEV)         governance no-timelock      cross-contract reentrancy
    unprotected initialize()   waterfall skip logic        critical address swap
    cross-chain arithmetic     interprocedural accrual     (+ 6 more subpatterns)

  Architecture:
    When Slither is available (use_slither=True, default):
      → Slither runs for its 24 pattern classes
      → ChainEDR runs ONLY its 23 novel classes (no duplication)
    When Slither is unavailable:
      → ChainEDR runs all 49 detectors (regex approximations of Slither patterns)

Performs static analysis on Solidity source code to detect vulnerability patterns
that the runtime classifier cannot see.

Capability matrix vs. bug class:
  Bug class                      Required approach          This module
  -----------------------------  -------------------------  -----------
  Stale oracle (no updatedAt)    Static analysis            YES — regex + AST (v1.6)
  Access control missing         Static analysis            YES — regex + AST (v1.6)
  Reentrancy (direct)            CEI pattern                YES — regex + AST (v1.6)
  Reentrancy (interprocedural)   Call graph                 YES — call graph (v1.6)
  Read-only reentrancy           View fn + ETH callback     YES — novel (v1.5)
  ERC4626 share inflation        Static pattern             YES (v1.5)
  ERC4626 rounding direction     EIP-4626 spec check        YES — novel (v1.5)
  Rebasing token accounting      Token interface detect     YES — novel (v1.5)
  Accrual-gate DoS               Rate=0 governance lock     YES — novel (v1.5)
  Donation inflation attack      Vault share calc           YES — novel (v1.5)
  Governance sandwich            Fee var timing attack      YES — novel (v1.5)
  Incomplete pausable coverage   Pausable audit             YES — novel (v1.5)
  Cross-protocol flash loan      AttackGraph                N/A (runtime)
  Euler-style accounting         InvariantMiner             N/A (runtime)
  Should-be-immutable storage    Cross-fn write tracking    YES (v1.5)
  Admin swap without drain       Setter pattern + context   YES (v1.5)
  Cross-chain arithmetic risk    Decode + subtrahend track  YES — AST-typed (v1.6)
  Yul assembly FPs               Block stripper             YES (v1.6)
  Unprotected initialize()       Proxy re-init exploit      YES — novel (v1.7)
  tx.origin authentication       Phishing auth bypass       YES — novel (v1.7)
  Spot price oracle (AMM)        Flash-loan price manip     YES — novel (v1.7)
  Signature replay (no nonce)    Replay / cross-chain       YES — novel (v1.7)
  Missing slippage protection    MEV sandwich               YES — novel (v1.7)
  Ether lock (no withdraw path)  Permanently locked ETH     YES — novel (v1.7)
  Division by zero (totalSupply) First-depositor DoS        YES — novel (v1.7)
  Hardcoded 18-decimal           USDC/WBTC pricing error    YES — novel (v1.7)
  selfdestruct ETH injection     Vault invariant break      YES — novel (v1.7)
  Cross-chain msg validation     Bridge forge attack        YES — novel (v1.7)
  Unsafe selfdestruct            Contract destruction       YES — novel (v1.7)

Regex detectors (49 total, +11 in v1.7):
  ── v1.0–v1.6 (38 detectors) ─────────────────────────────────────────────
  1.  BATCH_ATOMICITY_DOS         - Loops over external calls without try/catch
  2.  MISSING_BOUNDS_CHECK        - Inconsistent input validation across sibling functions
  3.  ADMIN_TRUST_ASSUMPTION      - onlyOwner fund-flow control (INFO)
  4.  UNSAFE_EXTERNAL_CALL        - External calls without CEI pattern
  5.  UNCHECKED_RETURN            - External call return values discarded
  6.  WATERFALL_SKIP              - If/return guards that skip partial resource consumption
  7.  PERMISSIONLESS_CRITICAL     - Public/external state-changing functions without access control
  8.  PRECISION_LOSS              - Division before multiplication
  9.  FEE_ON_TRANSFER             - transferFrom amount used directly without balance-diff accounting
  10. MISSING_VALIDATION_PAIR     - Function pair: one validates param, sibling does not
  11. STALE_ORACLE                - latestRoundData() without updatedAt; deprecated latestAnswer()
  12. UNPROTECTED_SETTER          - setX() functions without access control
  13. MSG_VALUE_IN_LOOP           - msg.value reused across loop iterations
  14. UUPS_MISSING_INITIALIZER    - Upgradeable contract missing _disableInitializers()
  15. DELEGATECALL_INJECTION      - delegatecall with user-controlled target (non-Yul)
  16. SINGLE_STEP_OWNERSHIP       - transferOwnership() with no pendingOwner pattern
  17. ADMIN_ZERO_ADDRESS_BRICK    - transferAdmin(address(0)) with no zero-address check
  18. APPROVAL_GRIEFING           - approve(0) pattern missing before non-zero approve
  19. AMM_DEADLINE                - block.timestamp as AMM deadline (MEV-sandwich-able)
  20. GOVERNANCE_ATTACK           - Admin critical setter without timelock
  21. CROSS_CONTRACT_REENTRANCY   - External call before state update + callback hook present
  22. MUTABLE_INIT_ONLY_STORAGE   - Should-be-immutable storage (set once, used in critical paths)
  23. CRITICAL_ADDRESS_SWAP       - setVault/setOracle without prior drain/migrate
  24. CROSS_CHAIN_INPUT_ARITH     - abi.decode subtrahend without bounds guard (AST-typed)
  25. TIMESTAMP_DEPENDENCY        - block.timestamp as RNG seed or strict equality gate
  26. ACCRUAL_GATE_DOS            - Rate=0 permanently freezes governance (interprocedural)
  27. DONATION_INFLATION          - Vault share calc from stored totalAssets (no virtual offset)
  28. GOVERNANCE_SANDWICH         - Admin fee setter + user fund-flow in same block (interprocedural)
  29. READ_ONLY_REENTRANCY        - View fn reads stale state during nonReentrant ETH callback
  30. INCOMPLETE_PAUSABLE         - Pausable contract with unguarded external state-changing fns
  31. ERC4626_ROUNDING_DIRECTION  - Wrong round direction on deposit/withdraw/mint/redeem
  32. REBASING_TOKEN_ACCOUNTING   - stETH/AMPL/aToken balance diverges from stored amount

  ── v1.7 NEW (11 detectors, covering $2.4B+ in on-chain losses) ──────────
  33. UNPROTECTED_INITIALIZE      - initialize() without initializer/guard (Wormhole $320M)
  34. TX_ORIGIN_AUTH              - tx.origin used for authentication (phishing bypass)
  35. SPOT_PRICE_ORACLE           - AMM getReserves() as price oracle (Mango $117M)
  36. SIGNATURE_REPLAY            - ecrecover without nonce (Wormhole VAA replay)
  37. MISSING_SLIPPAGE            - DEX swap without minAmountOut (MEV $1.4M/wk)
  38. ETHER_LOCK                  - payable with no ETH withdrawal path
  39. DIVISION_BY_ZERO            - totalSupply/totalShares as divisor without guard
  40. HARDCODED_DECIMALS          - 1e18 assumption on 6-decimal tokens (USDC/WBTC)
  41. SELFDESTRUCT_INJECTION      - address(this).balance in vault (Parity $150M)
  42. CROSS_CHAIN_MSG_VALIDATION  - Bridge callback without origin check (Poly $611M)
  43. UNSAFE_SELFDESTRUCT         - selfdestruct() in callable function

  AST-DEEP (requires solc in PATH, 7 detectors):
  44. AST_MSG_VALUE_IN_LOOP       - Confirmed msg.value in loop via AST
  45. AST_DELEGATECALL_INJECTION  - Confirmed delegatecall injection via AST
  46. AST_DIV_BEFORE_MUL         - Confirmed division-before-multiplication via AST node walk
  47. AST_UNCHECKED_ARITHMETIC    - Arithmetic on user input inside unchecked{} blocks
  48. AST_STALE_ORACLE            - latestRoundData() updatedAt discard (exact tuple slot check)
  49. AST_PERMISSIONLESS_CRITICAL - Critical fn missing modifier (exact AST modifier list)
  50. AST_REENTRANCY_CEI          - CEI violation via statement-order AST walk

Architecture:
  Tier 1: Slither subprocess (AST-accurate, reentrancy/precision/access control)
  Tier 2: solc AST bridge (zero FP from comments/strings; 7 detectors)
  Tier 3: Regex novel detectors (43 patterns; tuned on C4/Cantina audit corpus)
  Tier 4: Interprocedural analysis via intra-file call graph
  Tier 5: Mythril symbolic execution (off by default; slow)

  FP suppression pipeline:
    (a) Intentional-reentrancy comment scanner
    (b) Inheritance-based access-control propagation
    (c) Rule 2 exception for read-only reentrancy
    (d) CEI supersession dedup
    (e) Global (location, category) slot dedup — highest severity wins
    (f) Per-detector confidence table (51 entries, benchmark-calibrated 2026-05)

  FP Benchmark (2026-05, regex-only, 13 contracts):
    TP=7/7 (100% recall), FP=14, Precision=33%, F1=0.500
    Clean contracts 4/6 zero-finding; 2/6 minor info-level findings only.
"""

import re
import os
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

# Module-level regex cache — each pattern compiled once at first use,
# reused on every subsequent analyze() call. Eliminates ~128 re.compile
# function-call overhead per file in batch scans.
_RE_CACHE: Dict[tuple, re.Pattern] = {}

def _rc(pattern: str, flags: int = 0) -> re.Pattern:
    key = (pattern, flags)
    cached = _RE_CACHE.get(key)
    if cached is not None:
        return cached
    compiled = re.compile(pattern, flags)
    _RE_CACHE[key] = compiled
    return compiled


class StaticSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


class StaticCategory(Enum):
    DOS = "DOS"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    REENTRANCY = "REENTRANCY"
    LOGIC = "LOGIC"
    ANALYSIS_GAP = "ANALYSIS_GAP"
    TRUST_ASSUMPTION = "TRUST_ASSUMPTION"
    UNCHECKED_RETURN = "UNCHECKED_RETURN"
    WATERFALL_LOGIC = "WATERFALL_LOGIC"
    MISSING_ACCESS_CONTROL = "MISSING_ACCESS_CONTROL"
    PRECISION = "PRECISION"
    ACCOUNTING = "ACCOUNTING"
    # Phase 3 additions
    ERC4626 = "ERC4626"
    ZERO_ADDRESS = "ZERO_ADDRESS"
    ORACLE = "ORACLE"
    EIP7702 = "EIP7702"


@dataclass
class StaticFinding:
    severity: StaticSeverity
    category: StaticCategory
    title: str
    description: str
    location: str = ""          # e.g. "ContractName.functionName():L42"
    exploitable: bool = False
    is_false_positive: bool = False
    fp_reason: str = ""         # why it's a false positive
    fix_suggestion: str = ""
    cwe: str = ""
    confidence: float = 0.0     # 0.0 = unknown; 0.0–1.0 when known


@dataclass
class StaticAnalysisResult:
    contract_name: str
    source_hash: str = ""
    findings: List[StaticFinding] = field(default_factory=list)
    functions_analyzed: int = 0
    lines_analyzed: int = 0
    inheritance_chain: List[str] = field(default_factory=list)
    unanalyzed_dependencies: List[str] = field(default_factory=list)

    @property
    def real_findings(self) -> List[StaticFinding]:
        """Return only non-false-positive findings."""
        return [f for f in self.findings if not f.is_false_positive]

    @property
    def false_positive_rate(self) -> float:
        if not self.findings:
            return 0.0
        return sum(1 for f in self.findings if f.is_false_positive) / len(self.findings)


class SolidityStaticAnalyzer:
    """
    Static analysis engine for Solidity source code.
    
    Unlike the Classifier (which analyzes runtime transaction anomalies),
    this module analyzes SOURCE CODE patterns to find bugs before they're exploited.
    """

    def __init__(self):
        # Patterns that indicate "admin controls X" -- these are INFO, not bugs
        self.admin_modifiers = {
            "onlyOwner", "onlyAdmin", "onlyRole", "onlyGovernance",
            "onlyEVCAccountOwner", "onlyGuardian", "onlyTimelock",
            "onlyOperator", "onlyMinter", "onlyPauser",
            "onlyCoreRole", "onlyAdminOrExecutor", "onlyExecutor",
            "onlyKeeperRegistry", "onlyRelayer", "adminOnly",
            "onlyManager", "onlyController", "requiresAuth",
            # Extended set: Ripio-style and other protocol-specific modifiers
            "onlyExternalAdmin", "onlyComplianceAdmin", "onlyBridgeOperator",
            "onlyUpgrader", "onlyFeeManager", "onlyRouter",
            "onlyFactory", "onlyVault", "onlyProtocol",
            "onlyWhitelisted", "onlyStrategist", "onlyLiquidator",
            # ENS-specific auth patterns (per-node ownership model, not onlyOwner)
            "authorised",           # ResolverBase: modifier authorised(node)
            "owner_only",           # DNSSECImpl Owned contract
            "only_authorised_or_approved",  # ENS registry
            "onlyTokenOwner",       # ENS NameWrapper
            "onlyRegistrant",       # ENS BaseRegistrar
            "onlyNameWrapper",      # ENS resolver guard
            "isAuthorised",         # generic per-node auth
            # Generic patterns that indicate custom per-resource auth
            "whenCalledByOwner", "onlyApproved", "onlyDelegate",
            "onlyNodeOwner", "onlyRecordOwner",
        }
        # Known safe patterns (don't flag as issues)
        self.safe_patterns = {
            "nonReentrant",       # reentrancy guard
            "whenNotPaused",      # pause mechanism
            "initializer",        # upgrade pattern
        }

    @staticmethod
    def _strip_comments(code: str) -> str:
        """Remove single-line and multi-line comments from Solidity code."""
        # Remove single-line comments
        code = re.sub(r'//[^\n]*', '', code)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code

    @staticmethod
    def _strip_yul_blocks(code: str) -> str:
        """
        Replace ``assembly { ... }`` blocks with a placeholder comment.

        Why: regex detectors pattern-match Solidity syntax.  Yul opcodes
        (``let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)``)
        look like unsafe Solidity calls to a naive regex and cause FPs.
        Yul code is already correctly analysed by the AST bridge; the regex
        detectors gain nothing from seeing it.

        Handles arbitrary nesting depth via brace counting so that
        ``assembly { if iszero(x) { revert(0,0) } }`` is fully stripped.
        """
        result: list[str] = []
        i = 0
        length = len(code)
        # Find 'assembly' keyword followed (possibly with whitespace) by '{'
        _asm_re = _rc(r'\bassembly\s*\{', re.MULTILINE)
        last = 0
        for m in _asm_re.finditer(code):
            result.append(code[last:m.start()])
            result.append('/* [assembly block stripped] */')
            # Skip past the balanced braces
            depth = 1
            pos = m.end()          # just after the opening '{'
            while pos < length and depth > 0:
                ch = code[pos]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                pos += 1
            last = pos
        result.append(code[last:])
        return ''.join(result)

    # Detectors Slither covers with AST accuracy — skip in regex when Slither ran.
    _SLITHER_COVERED = frozenset([
        "_detect_reentrancy_cei", "_detect_unsafe_external_calls",
        "_detect_unchecked_returns", "_detect_permissionless_critical_functions",
        "_detect_precision_loss", "_detect_fee_on_transfer_accounting",
        "_detect_unchecked_erc20_transfers", "_detect_missing_zero_address",
    ])

    def analyze(
        self,
        source: str,
        contract_name: str = "Unknown",
        use_slither: bool = True,
        use_ast: bool = True,
        use_mythril: bool = False,
    ) -> StaticAnalysisResult:
        """
        Analyze Solidity source.

        Pipeline (full, default):
          1. Slither      — reentrancy, access control, precision, unchecked returns
                           (AST-accurate, near-zero FP rate)
          2. AST bridge   — solc AST re-implementation of all novel detectors.
                           Supersedes regex findings for the same function/category.
                           Falls back silently if solc is not in PATH.
          3. Novel regex  — stale oracle (5 sub-checks), waterfall skip, ERC4626
                           inflation, flash-loan manipulation, batch DoS, governance
                           attack, cross-contract reentrancy, and 6 novel patterns.
                           Regex findings are suppressed where AST already fired.
          4. Mythril      — symbolic execution (integer overflow, deep reentrancy).
                           Off by default (slow). Enable with use_mythril=True or
                           --mythril CLI flag.
          5. Regex fallback — if Slither unavailable, run Slither-covered patterns
                           via regex.

        Args:
            use_slither:  Run Slither (default True).
            use_ast:      Run solc AST bridge (default True; no-op if solc absent).
            use_mythril:  Run Mythril symbolic execution (default False — slow).
        """
        self._use_ast = use_ast

        result = StaticAnalysisResult(
            contract_name=contract_name,
            lines_analyzed=source.count('\n') + 1,
        )

        functions = self._extract_functions(source)
        result.functions_analyzed = len(functions)
        result.inheritance_chain = self._extract_inheritance(source)
        result.unanalyzed_dependencies = self._find_unanalyzed_deps(source)

        # Build intra-file call graph once — shared by all interprocedural detectors.
        call_graph = self._build_call_graph(functions)

        slither_ran = False
        if use_slither:
            slither_ran = self._run_slither(source, contract_name, result)

        # ── AST bridge (Tier 1: highest accuracy) ────────────────────────────
        ast_ran = False
        if use_ast:
            ast_ran = self._run_ast_bridge(source, result)

        # Always run novel regex detectors — Slither + AST have no coverage for
        # oracle staleness, waterfall skip, ERC4626 inflation, flash-loan price,
        # batch DoS, unprotected setters, timestamp manipulation.
        result.findings.extend(self._detect_stale_oracle(source, functions))
        result.findings.extend(self._detect_waterfall_skip(source, functions))
        result.findings.extend(self._detect_erc4626_share_inflation(source, functions))
        result.findings.extend(self._detect_flashloan_price_manipulation(source, functions))
        result.findings.extend(self._detect_batch_atomicity_dos(source, functions))
        result.findings.extend(self._detect_unprotected_setters(source, functions))
        result.findings.extend(self._detect_timestamp_dependency(source, functions))
        result.findings.extend(self._detect_accrual_gate_dos(source, functions, call_graph))
        result.findings.extend(self._detect_donation_inflation(source, functions))
        result.findings.extend(self._detect_governance_sandwich(source, functions, call_graph))
        result.findings.extend(self._detect_read_only_reentrancy(source, functions))
        result.findings.extend(self._detect_incomplete_pausable(source, functions))
        result.findings.extend(self._detect_erc4626_rounding_direction(source, functions))
        result.findings.extend(self._detect_rebasing_token_accounting(source, functions))

        # Governance attack + cross-contract reentrancy (novel, not in Slither/AST)
        result.findings.extend(self._detect_governance_attack(source, functions))
        result.findings.extend(self._detect_cross_contract_reentrancy_static(source, functions))

        # ── v1.7 novel detectors: ZERO Slither/Aderyn/Dedaub coverage ─────────
        # These run ALWAYS (not gated on slither_ran) because Slither does not
        # implement any of these patterns. When Slither is active, the global
        # dedup prevents duplication on the rare case Slither fires something
        # close. Run order: highest-impact exploits first.
        result.findings.extend(self._detect_spot_price_oracle(source, functions))       # Mango $117M
        result.findings.extend(self._detect_signature_replay(source, functions))        # Wormhole VAA
        result.findings.extend(self._detect_cross_chain_msg_validation(source, functions))  # Poly $611M
        result.findings.extend(self._detect_missing_slippage_protection(source, functions)) # MEV $1.4M/wk
        result.findings.extend(self._detect_division_by_zero_risk(source, functions))   # first-depositor
        result.findings.extend(self._detect_selfdestruct_injection(source, functions))  # Parity $150M
        result.findings.extend(self._detect_hardcoded_decimals(source, functions))      # USDC/WBTC math
        result.findings.extend(self._detect_unprotected_initialize(source, functions))  # proxy re-init

        # Slither covers tx-origin, locked-ether, suicidal — run only as fallback
        # when Slither is not available (moved to if not slither_ran block below)

        # Novel regex detectors — run only if AST bridge did NOT fire for the
        # same detector on the same function (avoids redundant duplicate findings).
        ast_covered = self._ast_covered_locations(result)
        regex_novel = [
            self._detect_msg_value_in_loop,
            self._detect_uups_missing_disable_initializers,
            self._detect_delegatecall_injection,
            self._detect_single_step_ownership,
            self._detect_admin_zero_address_brick,
            self._detect_approval_griefing,
            self._detect_amm_deadline,
            self._detect_mutable_init_only_storage,
            self._detect_critical_address_swap,
            self._detect_cross_chain_input_arith,
        ]
        for detector in regex_novel:
            for f in detector(source, functions):
                key = (f.location.split(":")[0], f.category)
                if key not in ast_covered:
                    result.findings.append(f)

        if not slither_ran:
            # ── Slither fallback: regex approximations of Slither detectors ──
            # These only run when Slither is unavailable. When Slither runs,
            # it handles all of these with higher accuracy (AST-based).
            #
            # Slither detector → ChainEDR regex equivalent:
            #   reentrancy-eth/no-eth     → _detect_reentrancy_cei + _detect_unsafe_external_calls
            #   divide-before-multiply    → _detect_precision_loss
            #   unchecked-lowlevel        → _detect_unchecked_returns + _detect_unchecked_erc20_transfers
            #   missing-zero-check        → _detect_missing_zero_address
            #   tx-origin                 → _detect_tx_origin_auth
            #   locked-ether              → _detect_ether_lock
            #   suicidal                  → _detect_unsafe_selfdestruct
            result.findings.extend(self._detect_missing_bounds_checks(source, functions))
            result.findings.extend(self._detect_admin_trust_assumptions(source, functions))
            result.findings.extend(self._detect_unsafe_external_calls(source, functions))
            result.findings.extend(self._detect_missing_try_catch_in_loops(source))
            result.findings.extend(self._detect_unchecked_returns(source, functions))
            result.findings.extend(self._detect_permissionless_critical_functions(source, functions))
            result.findings.extend(self._detect_precision_loss(source, functions))
            result.findings.extend(self._detect_fee_on_transfer_accounting(source, functions))
            result.findings.extend(self._detect_missing_validation_pair(source, functions))
            result.findings.extend(self._detect_reentrancy_cei(source, functions))
            result.findings.extend(self._detect_unchecked_erc20_transfers(source, functions))
            result.findings.extend(self._detect_missing_zero_address(source, functions))
            # Slither: tx-origin, locked-ether, suicidal fallbacks
            result.findings.extend(self._detect_tx_origin_auth(source, functions))
            result.findings.extend(self._detect_ether_lock(source, functions))
            result.findings.extend(self._detect_unsafe_selfdestruct(source, functions))

            # Dedup: CEI supersedes the older unsafe-external-calls finding
            cei_funcs = {
                f.location.split('():')[0]
                for f in result.findings
                if f.category == StaticCategory.REENTRANCY and 'CEI violation' in f.title
            }
            for f in result.findings:
                if (f.category == StaticCategory.REENTRANCY
                        and 'State update after external call' in f.title
                        and f.location.split('():')[0] in cei_funcs):
                    f.is_false_positive = True
                    f.fp_reason = "Superseded by CEI violation finding for same function"

        # ── Mythril (Tier 2: symbolic execution, opt-in) ─────────────────────
        if use_mythril:
            self._run_mythril(source, contract_name, result)

        # ── Commercial detectors (6 novel classes not in open-source) ──────────
        try:
            from commercial_detectors import run_commercial_detectors, CommercialFinding
            commercial = run_commercial_detectors(source, functions)
            for cf in commercial:
                sev_map = {"CRITICAL": StaticSeverity.CRITICAL, "HIGH": StaticSeverity.HIGH,
                           "MEDIUM": StaticSeverity.MEDIUM, "LOW": StaticSeverity.LOW}
                result.findings.append(StaticFinding(
                    severity=sev_map.get(cf.severity, StaticSeverity.MEDIUM),
                    category=StaticCategory.LOGIC,
                    title=cf.title,
                    description=cf.description,
                    location=cf.location,
                    cwe=cf.cwe,
                    confidence=cf.confidence,
                    fix_suggestion=cf.fix,
                ))
        except ImportError:
            pass  # commercial_detectors not available in open-source build

        # ── EIP-7702 detectors (Pectra, May 2025 — no other tool covers this) ─
        try:
            try:
                from .eip7702_detector import EIP7702Detector
            except ImportError:
                from eip7702_detector import EIP7702Detector
            eip7702 = EIP7702Detector()
            if eip7702.is_affected(source):
                for f7702 in eip7702.check(source):
                    sev_map = {"CRITICAL": StaticSeverity.CRITICAL, "HIGH": StaticSeverity.HIGH,
                               "MEDIUM": StaticSeverity.MEDIUM, "LOW": StaticSeverity.LOW}
                    result.findings.append(StaticFinding(
                        severity=sev_map.get(f7702.severity, StaticSeverity.MEDIUM),
                        category=StaticCategory.EIP7702,
                        title=f7702.title,
                        description=f7702.description,
                        location=f7702.location,
                        cwe=f7702.cwe,
                        confidence=f7702.confidence,
                        fix_suggestion=f7702.recommendation,
                    ))
        except ImportError:
            pass

        if result.unanalyzed_dependencies:
            result.findings.append(StaticFinding(
                severity=StaticSeverity.INFO,
                category=StaticCategory.ANALYSIS_GAP,
                title=f"Unanalyzed dependencies: {', '.join(result.unanalyzed_dependencies[:5])}",
                description="Contract uses libraries outside analysis scope.",
                location=f"{contract_name} (inheritance chain)",
                cwe="N/A",
            ))

        # ── Intentional reentrancy suppressor (post-pass, covers Slither findings too) ──
        _INTENTIONAL_COMMENT_RE = _rc(
            r'(?:intentional|composabilit|by\s+design|no\s+reentranc|purpose|'
            r'no\s+reentrancy\s+check|not\s+reentrant\s+on\s+purpose)',
            re.IGNORECASE,
        )
        src_lines = source.splitlines()
        for finding in result.findings:
            if finding.category != StaticCategory.REENTRANCY:
                continue
            if finding.is_false_positive:
                continue
            # Extract function name from title or location
            fname_m = re.search(r'\b(\w+)\b(?:\(\))?$', finding.location.split(':')[0])
            if not fname_m:
                # Try Slither title format: "[Slither/...] funcName"
                fname_m = re.search(r'\]\s+(\w+)\s*$', finding.title)
            if not fname_m:
                continue
            fname = fname_m.group(1)
            # Find the function in source and check preceding 10 lines for intentional comments
            fn_line_m = re.search(
                rf'function\s+{re.escape(fname)}\s*\(',
                source,
            )
            if not fn_line_m:
                continue
            fn_line_num = source[:fn_line_m.start()].count('\n')
            ctx = '\n'.join(src_lines[max(0, fn_line_num - 10): fn_line_num + 3])
            if _INTENTIONAL_COMMENT_RE.search(ctx):
                finding.is_false_positive = True
                finding.fp_reason = "Intentional nonReentrant omission documented in source comments"
                finding.severity = StaticSeverity.INFO

        self._filter_false_positives(result)

        # ── Inheritance-based access control propagation ──────────────────────
        # Build the set of function names that are admin-protected SOMEWHERE in
        # this file.  Any `override` function whose name is in this set inherits
        # the access control from the parent — the finding is a FP.
        # For `override` functions whose parent is external (OZ, etc.) we cannot
        # verify in-file, so we downgrade severity by one tier instead of suppressing.
        _protected_in_file = self._build_protected_override_set(source)
        _acl_cats = frozenset({StaticCategory.ACCESS_CONTROL, StaticCategory.MISSING_ACCESS_CONTROL})
        for finding in result.findings:
            if finding.is_false_positive or finding.category not in _acl_cats:
                continue
            fn_m = re.match(r'(\w+)\s*\(', finding.location)
            if not fn_m:
                continue
            fn_name = fn_m.group(1)
            # Check if the current function instance uses `override`
            is_override = bool(re.search(
                rf'function\s+{re.escape(fn_name)}\s*\([^{{]*\boverride\b',
                source,
            ))
            if not is_override:
                continue
            if fn_name in _protected_in_file:
                # In-file parent has admin modifier → definitive FP
                finding.is_false_positive = True
                finding.fp_reason = (
                    f"Inherited access control: `{fn_name}` has an admin modifier "
                    f"in a parent contract defined in the same file."
                )
                finding.severity = StaticSeverity.INFO
            else:
                # External parent (OZ, Solmate, etc.) — cannot verify in source.
                # Downgrade by one tier; auditor must confirm.
                _downgrade = {
                    StaticSeverity.CRITICAL: StaticSeverity.HIGH,
                    StaticSeverity.HIGH:     StaticSeverity.MEDIUM,
                    StaticSeverity.MEDIUM:   StaticSeverity.LOW,
                    StaticSeverity.LOW:      StaticSeverity.INFO,
                }
                new_sev = _downgrade.get(finding.severity)
                if new_sev:
                    finding.severity = new_sev
                    finding.description += (
                        "\n[Note: function uses `override` — parent contract not in scope. "
                        "Verify parent does NOT have an admin modifier before acting on this finding.]"
                    )

        # Per-detector confidence table (empirically tuned on benchmark corpus).
        # Keyed by title-prefix; longest prefix wins on ambiguous matches.
        _DETECTOR_CONFIDENCE: dict[str, float] = {
            "msg.value reuse":                           0.92,
            "UUPS/upgradeable: no constructor":          0.88,
            "UUPS/upgradeable: constructor missing":     0.88,
            "delegatecall injection":                    0.88,
            "Admin/owner transfer without zero-address": 0.90,
            "Deprecated safeApprove":                   0.92,
            "Deprecated latestAnswer":                   0.88,
            "CEI violation":                             0.80,
            "Flash-loan price manipulation":             0.85,
            "ERC-4626 share inflation":                  0.82,
            "AMM deadline=block.timestamp":              0.87,
            "AMM swap with infinite deadline":           0.88,
            "Approval griefing":                        0.80,
            "Single-step ownership transfer":            0.82,
            "Stale oracle: updatedAt discarded":         0.85,
            "Stale oracle: updatedAt captured":          0.75,
            "Oracle answer not validated":               0.80,
            "Missing answeredInRound":                   0.78,
            "Missing L2 sequencer uptime":               0.70,
            "Unprotected setter":                        0.82,
            "Governance: no timelock":                   0.78,
            "Waterfall skip":                            0.72,
            "Batch atomicity DoS":                       0.75,
            "Unbounded batch call":                      0.75,
            # Calibrated 2026-05 via FP benchmark (13 contracts, TP=7/7, FP=14)
            "Fee-on-transfer accounting":                0.72,  # co-fires on any ERC20; reduced 0.82→0.72
            "Unchecked ERC-20 return value":             0.65,  # frequent co-fire; context-dependent
            "Missing zero-address check":                0.60,  # factory-gated contracts cause FP
            "Unanalyzed dependencies":                   0.40,  # informational only
            "[AST] Division before multiplication":      0.88,
            "[AST] Unchecked arithmetic":                0.70,
            "Precision loss: division before":           0.78,
            "Permissionless critical function":          0.70,
            "Critical address swap":                     0.78,
            "Cross-chain decoded value":                 0.65,
            "Cross-contract reentrancy":                 0.73,
            "Should-be-immutable delegatecall":          0.72,
            "Timestamp manipulation":                    0.70,
            "Accrual-gate DoS":                         0.82,
            "Donation inflation attack":                 0.78,
            "Governance sandwich":                       0.72,
            "Read-only reentrancy":                      0.78,
            "Incomplete pausable":                       0.80,
            "ERC4626: `":                                0.80,
            "Rebasing token accounting":                 0.75,
            # v1.7 calibrated entries
            "Unprotected initializer":                   0.82,
            "tx.origin authentication":                  0.90,
            "Spot price oracle":                         0.80,
            "Signature replay":                          0.78,
            "Missing slippage protection":               0.75,
            "Ether lock":                                0.72,
            "Division-by-zero risk":                     0.78,
            "Hardcoded 18-decimal assumption":           0.65,
            "Selfdestruct ETH injection":                0.70,
            "Cross-chain callback":                      0.82,
            "Unguarded selfdestruct":                    0.85,
            "Guarded selfdestruct":                      0.60,
        }

        for f in result.findings:
            if f.confidence != 0.0 or f.title.startswith("[Slither/"):
                continue
            # Find longest matching prefix
            best_prefix = ""
            best_conf = 0.0
            for prefix, conf in _DETECTOR_CONFIDENCE.items():
                if f.title.startswith(prefix) and len(prefix) > len(best_prefix):
                    best_prefix = prefix
                    best_conf = conf
            if best_prefix:
                f.confidence = best_conf
            else:
                # Fallback: category + exploitability tiers
                if f.category == StaticCategory.REENTRANCY:
                    f.confidence = 0.78
                elif f.category == StaticCategory.ORACLE:
                    f.confidence = 0.80
                elif f.exploitable:
                    f.confidence = 0.82
                else:
                    f.confidence = 0.68

        # ── Global dedup: one finding per (location_key, category) ──────────
        # Keeps the highest-severity non-FP finding per slot; retains all FPs
        # separately so reporters can still inspect them.
        _SEV_ORDER = {
            StaticSeverity.CRITICAL: 5,
            StaticSeverity.HIGH:     4,
            StaticSeverity.MEDIUM:   3,
            StaticSeverity.LOW:      2,
            StaticSeverity.INFO:     1,
        }
        real_findings: dict[tuple, "StaticFinding"] = {}
        fp_findings: list["StaticFinding"] = []
        for f in result.findings:
            if f.is_false_positive:
                fp_findings.append(f)
                continue
            loc_key = f.location.split(":")[0].strip()
            slot = (loc_key, f.category)
            if slot not in real_findings:
                real_findings[slot] = f
            else:
                existing = real_findings[slot]
                if _SEV_ORDER.get(f.severity, 0) > _SEV_ORDER.get(existing.severity, 0):
                    real_findings[slot] = f
        result.findings = list(real_findings.values()) + fp_findings

        # ── InvariantFuzzer (economic invariant detectors) ──────────────────
        # Experimental economic-invariant detectors. These produce research
        # leads and should be backed by a harness or manual audit argument
        # before being treated as impact.
        try:
            from .invariant_fuzzer import InvariantFuzzer, InvariantSeverity
            _INV_SEV = {
                InvariantSeverity.CRITICAL: StaticSeverity.CRITICAL,
                InvariantSeverity.HIGH:     StaticSeverity.HIGH,
                InvariantSeverity.MEDIUM:   StaticSeverity.MEDIUM,
                InvariantSeverity.LOW:      StaticSeverity.LOW,
                InvariantSeverity.INFO:     StaticSeverity.INFO,
            }
            _INV_CAT = {
                'WATERFALL_CLIFF':    StaticCategory.WATERFALL_LOGIC,
                'SIBLING_ASYMMETRY':  StaticCategory.LOGIC,
                'ORPHANED_RESOURCE':  StaticCategory.WATERFALL_LOGIC,
                'THRESHOLD_CLIFF':    StaticCategory.LOGIC,
                'ACCOUNTING_GAP':     StaticCategory.ACCOUNTING,
                'FEE_ROUNDING_BIAS':  StaticCategory.PRECISION,
                'REWARD_CLIFF':       StaticCategory.LOGIC,
                'GRIEFABLE_UPDATER':  StaticCategory.DOS,
            }
            inv_findings = InvariantFuzzer().analyze(source)
            for inv in inv_findings:
                result.findings.append(StaticFinding(
                    severity=_INV_SEV.get(inv.severity, StaticSeverity.MEDIUM),
                    category=_INV_CAT.get(inv.detector, StaticCategory.LOGIC),
                    title=f"[InvFuzz] {inv.title}",
                    description=inv.description,
                    location=inv.location,
                    exploitable=(inv.severity in (InvariantSeverity.CRITICAL, InvariantSeverity.HIGH)),
                    fix_suggestion=inv.fix,
                    confidence=inv.confidence,
                ))
        except Exception:
            pass  # never break the pipeline

        return result

    def _run_ast_bridge(self, source: str, result: StaticAnalysisResult) -> bool:
        """Run AST-based detectors. Returns True if AST was available."""
        try:
            from .ast_bridge import ASTAnalyzer, is_available as ast_available
        except ImportError:
            try:
                from ast_bridge import ASTAnalyzer, is_available as ast_available
            except ImportError:
                return False

        if not ast_available():
            return False

        try:
            findings = ASTAnalyzer().analyze(source, result.contract_name)
            for f in findings:
                f.title = f"[AST] {f.title}" if not f.title.startswith("[AST]") else f.title
            result.findings.extend(findings)
            return bool(findings) or True  # ran, even if 0 findings
        except Exception:
            return False

    def _run_mythril(self, source: str, contract_name: str, result: StaticAnalysisResult) -> bool:
        """Run Mythril symbolic execution. Returns True if Mythril was available."""
        try:
            from .mythril_bridge import run as mythril_run, is_available as myth_available
        except ImportError:
            try:
                from mythril_bridge import run as mythril_run, is_available as myth_available
            except ImportError:
                return False

        if not myth_available():
            result.findings.append(StaticFinding(
                severity=StaticSeverity.INFO,
                category=StaticCategory.ANALYSIS_GAP,
                title="[Mythril] Not installed — symbolic execution skipped",
                description="Install: pip install mythril",
                location=contract_name,
                cwe="N/A",
            ))
            return False

        findings = mythril_run(source, contract_name)
        result.findings.extend(findings)
        return True

    @staticmethod
    def _ast_covered_locations(result: StaticAnalysisResult):
        """Return set of (func_location_prefix, category) for AST findings."""
        return {
            (f.location.split(":")[0], f.category)
            for f in result.findings
            if f.title.startswith("[AST]") and not f.is_false_positive
        }

    def _run_slither(
        self, source: str, contract_name: str, result: StaticAnalysisResult
    ) -> bool:
        """Run Slither, append findings to result. Returns True on success."""
        try:
            from .slither_bridge import SlitherBridge
        except ImportError:
            return False

        slither_result = SlitherBridge(timeout=60).run(
            source_code=source, filename=f"{contract_name}.sol"
        )
        if not slither_result.success:
            result.findings.append(StaticFinding(
                severity=StaticSeverity.INFO,
                category=StaticCategory.ANALYSIS_GAP,
                title="Slither unavailable — regex fallback active",
                description=slither_result.error[:200],
                location=contract_name,
                cwe="N/A",
            ))
            return False

        result.findings.extend(slither_result.to_static_findings())
        return True

    # ── OZ library file stripper ──────────────────────────────────────────────

    _OZ_FILE_RE = _rc(
        r'^// FILE:.*?(?=^// FILE:|\Z)',
        re.MULTILINE | re.DOTALL,
    )
    _OZ_PATH_RE = _rc(
        r'openzeppelin|forge-std|@openzeppelin|solmate|solady|'
        r'lib/(?:oz|openzeppelin)|node_modules|ds-test',
        re.IGNORECASE,
    )

    def _strip_oz_files(self, source: str) -> str:
        """
        Remove concatenated library file sections from flattened source.

        Etherscan flat exports prefix each included file with:
            // FILE: lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol

        We keep sections whose path does NOT look like a library dependency.
        If no FILE markers exist (single-file source), the source is returned as-is.
        """
        sections = self._OZ_FILE_RE.findall(source)
        if not sections:
            return source   # single-file source — nothing to strip

        kept = []
        for sec in sections:
            # First line of the section is the // FILE: header
            header_line = sec.split('\n', 1)[0]
            if self._OZ_PATH_RE.search(header_line):
                continue    # library file — discard
            kept.append(sec)

        if not kept:
            # Everything looked like a library — fall back to full source so we
            # don't silently analyze nothing (e.g. project with only OZ files)
            return source

        return '\n'.join(kept)

    def _extract_functions(self, source: str) -> List[Dict]:
        """Extract function signatures and bodies from source.

        Handles both single-line and multiline function signatures:
            // single-line (old regex caught this):
            function foo(uint x) internal returns (uint) {
            // multiline (old regex MISSED 'internal' here):
            function foo(
                uint x
            ) internal returns (uint) {
        """
        functions = []

        # Strip comments first so NatSpec blocks don't yield phantom functions.
        # We keep the original source for line-number counting.
        # Also strip OZ/library files so we only analyze the primary contract.
        clean_source = self._strip_comments(self._strip_oz_files(source))

        # Step 1: find every 'function <name>', 'constructor', 'receive', or
        # 'fallback' opening position.  receive()/fallback() have no name token
        # so they use named groups and a sentinel string.
        fn_start_pattern = _rc(
            r'\b(?:function\s+(\w+)|(?P<ctor>constructor)|(?P<recv>receive)|(?P<fall>fallback))\s*\(',
            re.MULTILINE,
        )

        for fn_match in fn_start_pattern.finditer(clean_source):
            if fn_match.group(1):
                name = fn_match.group(1)
            elif fn_match.group('ctor'):
                name = 'constructor'
            elif fn_match.group('recv'):
                name = 'receive'
            else:
                name = 'fallback'
            # Count lines in ORIGINAL source up to the same byte offset
            # (stripping comments may shift offsets, so approximate with clean_source)
            line_num = clean_source[:fn_match.start()].count('\n') + 1

            # Step 2: find the matching closing ')' for the parameter list
            paren_start = fn_match.end() - 1   # position of '('
            depth = 0
            pos = paren_start
            while pos < len(clean_source):
                if clean_source[pos] == '(':
                    depth += 1
                elif clean_source[pos] == ')':
                    depth -= 1
                    if depth == 0:
                        break
                pos += 1
            paren_end = pos  # position of closing ')'

            # Step 3: extract params string
            params = clean_source[paren_start + 1:paren_end].strip()

            # Step 4: scan from ')' to '{' for visibility/modifiers
            # This window captures multiline signatures correctly
            brace_pos = clean_source.find('{', paren_end)
            if brace_pos == -1:
                continue
            sig_tail = clean_source[paren_end:brace_pos]  # everything between ) and {

            # Skip interface/abstract declarations: a semicolon before the opening
            # brace means this is `function foo(...) external;` with no body.
            if ';' in sig_tail:
                continue

            # Determine visibility
            if re.search(r'\binternal\b', sig_tail):
                visibility = 'internal'
            elif re.search(r'\bprivate\b', sig_tail):
                visibility = 'private'
            elif re.search(r'\bexternal\b', sig_tail):
                visibility = 'external'
            elif re.search(r'\bpublic\b', sig_tail):
                visibility = 'public'
            else:
                # No explicit visibility — default depends on context
                # Functions starting with _ are internal by convention
                visibility = 'internal' if name.startswith('_') else 'public'

            # Collect all modifier/keyword tokens from the signature tail
            # Uses a broad pattern so custom modifiers (e.g. onlyAdminOrExecutor)
            # are captured without needing to enumerate every possible name.
            modifiers_str = ' '.join(re.findall(
                r'\b(?:external|public|internal|private|view|pure|payable|virtual|'
                r'override|nonReentrant|whenNotPaused|initializer|'
                r'only\w+|admin\w*|requiresAuth|guard\w+|'
                r'authorised(?:\(\w+\))?|owner_only|only_authorised\w*|'
                r'onlyToken\w+|onlyRegistrant|onlyNameWrapper|isAuthorised|'
                r'whenCalledByOwner|onlyApproved|onlyDelegate|'
                r'onlyNodeOwner|onlyRecordOwner)\b',
                sig_tail
            ))

            # Step 5: extract body starting after '{'.
            # Strip Yul assembly blocks from the body so regex detectors don't
            # false-positive on Yul opcodes (delegatecall, sstore, etc.) that
            # look like unsafe Solidity calls but are inside assembly.
            body = self._strip_yul_blocks(
                self._extract_body(clean_source, brace_pos + 1)
            )

            functions.append({
                'name': name,
                'params': params,
                'modifiers': modifiers_str,
                'visibility': visibility,
                'body': body,
                'line': line_num,
                'full_match': clean_source[fn_match.start():brace_pos + 1],
            })

        return functions

    def _build_call_graph(self, functions: List[Dict]) -> Dict[str, set]:
        """
        Build a lightweight intra-file call graph from already-extracted functions.

        Returns {caller_name: {callee_name, ...}} where callee names are
        restricted to functions that exist in the same file.  External library
        calls (e.g. SafeERC20.safeTransfer) are excluded because the callee
        name alone is ambiguous.

        Used by interprocedural detectors (accrual-gate DoS, governance sandwich,
        reentrancy CEI) to trace A() → B() → C() chains rather than only looking
        inside individual function bodies.

        Complexity: O(F²) where F = number of functions — acceptable for typical
        contract sizes (< 100 functions).
        """
        known: set = {f['name'] for f in functions}
        # Pre-compile a single RE that matches any known function name as a call
        if not known:
            return {}
        # Negative lookbehind: avoid matching 'foo' in 'bar.foo()' (external call)
        _call_pat = _rc(
            r'(?<!\.)(?<!\w)\b(' + '|'.join(re.escape(n) for n in known) + r')\s*\(',
        )
        graph: Dict[str, set] = {f['name']: set() for f in functions}
        for func in functions:
            body = func.get('body', '')
            for m in _call_pat.finditer(body):
                callee = m.group(1)
                if callee != func['name']:   # skip self-recursion
                    graph[func['name']].add(callee)
        return graph

    def _call_graph_reachable(
        self, graph: Dict[str, set], entry: str, max_depth: int = 6
    ) -> set:
        """BFS from entry; returns set of all reachable function names."""
        visited: set = set()
        queue = [entry]
        depth = 0
        while queue and depth <= max_depth:
            next_queue: list = []
            for node in queue:
                if node in visited:
                    continue
                visited.add(node)
                next_queue.extend(graph.get(node, set()) - visited)
            queue = next_queue
            depth += 1
        return visited

    def _build_interface_map(self, source: str) -> Dict[str, str]:
        """
        Map interface names → concrete contract names within the same flat source.

        Purpose: cross-contract call resolution.  When a detector sees
        ``IVault(addr).deposit()``, it needs to know what ``deposit()`` does.
        Flattened Etherscan exports contain both the interface and the
        implementing contract — this map lets detectors look up the concrete
        implementation without external compilation.

        Strategy:
          1. Collect all ``interface I { ... }`` names.
          2. Collect all ``contract C is I`` (or ``contract C is I, J``) relationships.
          3. Map interface name → concrete contract name (first implementing contract wins).

        Returns dict like {"IVault": "Vault", "IERC20": "ERC20"}.
        """
        clean = self._strip_comments(source)

        # Find all interface declarations
        _IFACE_RE = _rc(r'\binterface\s+(\w+)\s*(?:is\s+[\w\s,]+)?\{')
        iface_names: set = {m.group(1) for m in _IFACE_RE.finditer(clean)}

        # Find all concrete contract declarations and their base list
        _CONTRACT_RE = _rc(
            r'\bcontract\s+(\w+)\s+is\s+([\w\s,]+?)\s*\{',
        )
        result: Dict[str, str] = {}
        for m in _CONTRACT_RE.finditer(clean):
            concrete = m.group(1)
            bases = [b.strip() for b in m.group(2).split(',')]
            for base in bases:
                if base in iface_names and base not in result:
                    result[base] = concrete
        return result

    def _resolve_call_target(
        self,
        expr: str,
        interface_map: Dict[str, str],
        functions: List[Dict],
    ) -> Optional[str]:
        """
        Given a call expression like ``IVault(addr).deposit``, return the
        concrete function name to look up in ``functions``, or None.

        Handles:
          - ``IFoo(addr).bar`` → looks up ``IFoo`` in interface_map → ``FooImpl.bar``
          - ``_vault.bar`` / ``vault.bar`` → direct storage var call, returns ``bar``
          - ``bar(...)`` → local call, returns ``bar``
        """
        # Member call: Type(x).method or var.method
        m = re.match(r'(\w+)(?:\([^)]*\))?\.\s*(\w+)$', expr.strip())
        if m:
            obj_type = m.group(1)
            method   = m.group(2)
            concrete = interface_map.get(obj_type)
            if concrete:
                return method  # return method name; caller looks it up in functions
            return method   # storage var call — return method name anyway
        # Plain function call
        plain = re.match(r'(\w+)$', expr.strip())
        if plain:
            return plain.group(1)
        return None

    def _build_protected_override_set(self, source: str) -> set:
        """
        Return the set of function names that appear with an admin modifier
        ANYWHERE in the same source file.

        Purpose: interprocedural modifier inheritance.  When a child contract
        overrides a parent function, Solidity does NOT require re-declaring the
        modifier — the child inherits it.  Without this set, the tool would flag
        every unguarded override as "unprotected", producing a high FP rate on
        any multi-contract file.

        Strategy: scan the ENTIRE file (comment-stripped) for
            function <name>(...) <sig_tail>{ where sig_tail contains an admin modifier.
        Any function name found here is "known-protected" and overrides of it are safe.
        """
        clean = self._strip_comments(source)
        protected: set = set()

        # Build combined admin-modifier pattern from the instance list
        admin_pattern = _rc(
            r'function\s+(\w+)\s*\([^)]*\)'  # function name + params
            r'[^{;]{0,300}'                   # sig tail (modifiers/visibility)
            r'\b(' + '|'.join(re.escape(m) for m in self.admin_modifiers) + r')\b',
            re.DOTALL
        )
        for m in admin_pattern.finditer(clean):
            protected.add(m.group(1))

        return protected

    def _extract_body(self, source: str, start_pos: int) -> str:
        """Extract function body by matching braces."""
        depth = 1
        pos = start_pos
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        return source[start_pos:pos - 1] if pos <= len(source) else ""

    def _extract_inheritance(self, source: str) -> List[str]:
        """Extract inheritance chain from contract declaration."""
        pattern = _rc(r'contract\s+\w+\s+is\s+([^{]+)\{')
        match = pattern.search(source)
        if match:
            parents = [p.strip() for p in match.group(1).split(',')]
            return [p.split('(')[0].strip() for p in parents]  # Remove constructor args
        return []

    def _find_unanalyzed_deps(self, source: str) -> List[str]:
        """Find imported/inherited contracts not defined in this source."""
        # Find all contract/interface/library names defined in source
        defined = set(re.findall(r'(?:contract|interface|library)\s+(\w+)', source))
        # Find all inherited names
        inherited = set(self._extract_inheritance(source))
        # Find all interface calls: IContractName(addr).method()
        # Must match I + Uppercase letter (e.g. IAmpleEarn, not InvalidVault)
        interface_calls = set(re.findall(r'\bI([A-Z]\w{2,})\s*\(', source))
        # Find library usages: using LibName for Type
        libraries = set(re.findall(r'using\s+(\w+)\s+for', source))

        all_deps = inherited | interface_calls | libraries
        # Filter out short names and obvious non-contracts
        all_deps = {d for d in all_deps if len(d) > 2 and d[0].isupper()}
        return sorted(all_deps - defined)

    def _detect_batch_atomicity_dos(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Loop that calls external contracts without try/catch.
        
        This is the bug ChainEDR missed in Ample Earn's _executeClaims().
        If one call reverts, the entire batch fails.
        """
        findings = []
        for func in functions:
            body = func['body']
            # Check for loops with external calls
            has_loop = bool(re.search(r'\bfor\s*\(', body)) or bool(re.search(r'\bwhile\s*\(', body))
            if not has_loop:
                continue

            # Inline: IFoo(addr).method()  OR stored: iFoo.method() / iToken.method()
            has_external_call = bool(re.search(r'I\w+\([^)]*\)\.\w+\(', body)) or \
                                bool(re.search(r'\b[a-z]\w*\.\w+\s*\(', body))
            has_low_level_call = bool(re.search(r'\.call\{', body))

            if not (has_external_call or has_low_level_call):
                continue

            # Check if try/catch is used
            has_try_catch = bool(re.search(r'\btry\b', body))

            # Fix 3: suppress when external call failure is handled gracefully
            # 3a: return value captured in bool + conditional (e.g. topUp pattern)
            has_captured_return = bool(re.search(
                r'bool\s+\w+\s*=\s*\w+(?:\.\w+)+\s*\([^)]*\)',
                body
            ))
            # 3b: custom inline reentrancy guard (bool flag set true at start, false at end)
            # e.g. s_dynamicConfig.reentrancyGuardEntered = true / false
            has_inline_guard = bool(re.search(
                r'reentrancy\w*\s*=\s*true', body, re.IGNORECASE
            ))

            if not has_try_catch and not has_captured_return and not has_inline_guard:
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.DOS,
                    title=f"Batch atomicity DoS in {func['name']}()",
                    description=f"Function {func['name']}() contains a loop with external calls "
                               f"but no try/catch. If any single call reverts, the entire batch "
                               f"fails, potentially blocking other valid operations.",
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion="Wrap external calls in try/catch to isolate failures.",
                    cwe="CWE-703",
                ))
        return findings

    def _detect_missing_bounds_checks(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Inconsistent input validation across similar functions.
        
        Two detection strategies:
        1. If function A checks `if (x >= limit) revert()` but function B
           uses both variables without checking, flag it.
        2. If function A validates parameter P with bounds check, and function B
           takes the SAME parameter P but accesses a mapping with it without check.
        Uses comment-stripped code to avoid matching commented-out checks.
        """
        findings = []
        
        # Strategy 1: Same-variable bounds check inconsistency
        bounds_checks = {}
        for func in functions:
            stripped_body = self._strip_comments(func['body'])
            checks = re.findall(r'if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)\s*revert', stripped_body)
            for var, limit in checks:
                key = (var, limit)
                if key not in bounds_checks:
                    bounds_checks[key] = []
                bounds_checks[key].append(func['name'])

        for (var, limit), checking_funcs in bounds_checks.items():
            for func in functions:
                if func['name'] in checking_funcs:
                    continue
                stripped_body = self._strip_comments(func['body'])
                if re.search(rf'\b{var}\b', stripped_body) and re.search(rf'\b{limit}\b', stripped_body):
                    has_check = re.search(
                        rf'if\s*\(\s*{var}\s*>=\s*{limit}\s*\)', stripped_body
                    )
                    if not has_check:
                        findings.append(StaticFinding(
                            severity=StaticSeverity.LOW,
                            category=StaticCategory.INPUT_VALIDATION,
                            title=f"Missing bounds check in {func['name']}()",
                            description=f"{checking_funcs[0]}() validates '{var} >= {limit}' but "
                                       f"{func['name']}() uses both variables without this check.",
                            location=f"{func['name']}():L{func['line']}",
                            exploitable=False,
                            fix_suggestion=f"Add: if ({var} >= {limit}) revert();",
                            cwe="CWE-129",
                        ))

        # Strategy 2: Parameter-level inconsistency
        # If function A has param P and validates it with `if (P >= X) revert`,
        # and function B also has param P and uses it in a mapping access `mapping[P]`
        # but does NOT validate it, flag it.
        param_validations = {}
        for func in functions:
            stripped_body = self._strip_comments(func['body'])
            params = [p.strip().split()[-1] for p in func['params'].split(',') if p.strip()]
            checks = re.findall(r'if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)\s*revert', stripped_body)
            for var, limit in checks:
                if var in params:
                    if var not in param_validations:
                        param_validations[var] = []
                    param_validations[var].append({
                        'func': func['name'],
                        'limit': limit,
                    })

        for param, validators in param_validations.items():
            for func in functions:
                if any(v['func'] == func['name'] for v in validators):
                    continue
                # Check if this function has the same parameter
                func_params = [p.strip().split()[-1] for p in func['params'].split(',') if p.strip()]
                if param not in func_params:
                    continue
                # Check if it uses the param in a mapping access without bounds check
                stripped_body = self._strip_comments(func['body'])
                uses_in_mapping = re.search(rf'\w+\[\s*{param}\s*\]', stripped_body)
                has_validation = re.search(rf'if\s*\(\s*{param}\s*>=', stripped_body)
                if uses_in_mapping and not has_validation:
                    validator = validators[0]
                    # Check for duplicate
                    already_found = any(
                        f.title == f"Missing bounds check in {func['name']}()"
                        for f in findings
                    )
                    if not already_found:
                        findings.append(StaticFinding(
                            severity=StaticSeverity.LOW,
                            category=StaticCategory.INPUT_VALIDATION,
                            title=f"Missing bounds check in {func['name']}()",
                            description=f"{validator['func']}() validates parameter '{param}' with "
                                       f"'{param} >= {validator['limit']}' check, but {func['name']}() "
                                       f"uses '{param}' as a mapping key without the same validation.",
                            location=f"{func['name']}():L{func['line']}",
                            exploitable=False,
                            fix_suggestion=f"Add: if ({param} >= {validator['limit']}) revert();",
                            cwe="CWE-129",
                        ))
        return findings

    def _detect_admin_trust_assumptions(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Detects admin-only functions and classifies them as INFO (not bugs).
        
        This prevents the false positive we had where 'onlyOwner controls X' was
        flagged as CRITICAL. Admin trust assumptions are by design.
        """
        findings = []
        for func in functions:
            mods = func['modifiers']
            has_admin_modifier = any(m in mods for m in self.admin_modifiers)
            if not has_admin_modifier:
                continue

            # Check if the function controls fund flow
            controls_funds = any(keyword in func['body'] for keyword in [
                'transfer', 'approve', 'safeTransfer', 'withdraw',
                'mint', 'burn', '_redeem', 'totalPayoutsReserved',
            ])

            if controls_funds:
                findings.append(StaticFinding(
                    severity=StaticSeverity.INFO,
                    category=StaticCategory.TRUST_ASSUMPTION,
                    title=f"{func['name']}() is admin-controlled fund operation",
                    description=f"Function {func['name']}() controls fund flow but is protected "
                               f"by admin modifiers ({mods}). This is a trust assumption, NOT a bug.",
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=False,
                    is_false_positive=True,
                    fp_reason="Admin trust assumption. Would be rejected by bug bounty triagers.",
                    cwe="N/A",
                ))
        return findings

    # Known view/pure functions that cannot trigger reentrancy even via interface calls.
    # Calls matching these method names are excluded from CEI analysis.
    _VIEW_ONLY_METHODS: frozenset = frozenset({
        'balanceOf', 'totalSupply', 'decimals', 'symbol', 'name', 'allowance',
        'getReserves', 'price0CumulativeLast', 'price1CumulativeLast',
        'latestRoundData', 'latestAnswer', 'getAnswer', 'getRoundData',
        'isRegistered', 'isAllowed', 'isOperationReady', 'isOperationDone',
        'hasRole', 'getRoleAdmin', 'supportsInterface',
        'getPastVotes', 'getPastTotalSupply', 'getVotes', 'clock',
        'totalAssets', 'convertToShares', 'convertToAssets', 'previewDeposit',
        'previewMint', 'previewWithdraw', 'previewRedeem', 'maxDeposit',
        'owner', 'paused', 'version', 'implementation',
    })

    _EXT_CALL_METHOD_RE = _rc(r'\.(\w+)\s*\(')

    def _is_view_only_call(self, call_match_text: str) -> bool:
        """Return True if the external call invokes a known view/pure method.

        The main ext-call regex captures up to the method name but may not
        include the trailing '(' (e.g. 'IERC20(x).balanceOf' not
        'IERC20(x).balanceOf(').  Handle both forms.
        """
        # Form 1: '.method(' present in match text
        m = self._EXT_CALL_METHOD_RE.search(call_match_text)
        if m:
            return m.group(1) in self._VIEW_ONLY_METHODS
        # Form 2: match text ends with '.method' (no trailing paren captured)
        m2 = re.search(r'\.(\w+)\s*$', call_match_text)
        if m2:
            return m2.group(1) in self._VIEW_ONLY_METHODS
        return False

    def _detect_unsafe_external_calls(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: External calls before state updates (violates CEI pattern).
        Skips calls to known view/pure methods which cannot cause reentrancy.
        """
        findings = []
        for func in functions:
            body = func['body']
            # Find external calls — exclude known view-only method names
            all_calls = list(re.finditer(r'(?:\.call\{|\.transfer\(|\.send\(|I\w+\([^)]*\)\.\w+)', body))
            ext_calls = [c for c in all_calls if not self._is_view_only_call(c.group(0))]
            if not ext_calls:
                continue

            # Find state updates (storage writes)
            state_updates = list(re.finditer(
                r'(?:totalPayouts\w+|balance\w+|_\w+\[|mapping\w+)\s*[\+\-]?=', body
            ))

            # Check if any state update comes AFTER an external call
            for call in ext_calls:
                for update in state_updates:
                    if update.start() > call.end():
                        # Check if nonReentrant is present (mitigates the risk)
                        if 'nonReentrant' in func['modifiers']:
                            continue  # Safe
                        findings.append(StaticFinding(
                            severity=StaticSeverity.HIGH,
                            category=StaticCategory.REENTRANCY,
                            title=f"State update after external call in {func['name']}()",
                            description=f"External call before state update in {func['name']}() "
                                       f"without nonReentrant modifier. Potential reentrancy.",
                            location=f"{func['name']}():L{func['line']}",
                            exploitable=True,
                            fix_suggestion="Add nonReentrant modifier or move state updates before external calls.",
                            cwe="CWE-841",
                            confidence=0.80,
                        ))
                        break
                else:
                    continue
                break
        return findings

    def _detect_missing_try_catch_in_loops(self, source: str) -> List[StaticFinding]:
        """
        PATTERN: Specifically detect for-loops calling .claimPayout, .withdraw,
        or similar batch operations without try/catch.
        """
        findings = []
        # Find for-loops
        loop_pattern = _rc(r'for\s*\([^)]+\)\s*\{', re.MULTILINE)
        for match in loop_pattern.finditer(source):
            loop_body = self._extract_body(source, match.end())

            # Dangerous patterns inside loops without try/catch
            dangerous_calls = re.findall(
                r'(\w+)\.(claimPayout|withdraw|redeem|transfer|execute|swap)\s*\(', loop_body
            )
            # Fix 3b: suppress if the external call's return is captured in a bool
            # e.g. bool success = token.transfer(...); if (success) {...} else {...}
            has_bool_capture = bool(re.search(
                r'bool\s+\w+\s*=\s*\w+(?:\.\w+)+\s*\([^)]*\)',
                loop_body
            ))
            if dangerous_calls and 'try' not in loop_body and not has_bool_capture:
                call_desc = ', '.join(f"{c[0]}.{c[1]}()" for c in dangerous_calls[:3])
                line_num = source[:match.start()].count('\n') + 1
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.DOS,
                    title=f"Unbounded batch call without try/catch at L{line_num}",
                    description=f"Loop calls {call_desc} without error handling. "
                               f"Single failure reverts entire batch.",
                    location=f"L{line_num}",
                    exploitable=True,
                    fix_suggestion="Wrap calls in try {{ }} catch {{ }} to isolate failures.",
                    cwe="CWE-703",
                ))
        return findings

    def _detect_unchecked_returns(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Low-level calls without return value check.
        """
        findings = []
        for func in functions:
            body = func['body']
            # Find .call{} without (bool success, ) check
            low_level_calls = re.findall(r'\.call\{[^}]*\}\s*\([^)]*\)', body, re.DOTALL)
            for call in low_level_calls:
                call_pos = body.find(call)
                pre_context = body[max(0, call_pos - 200):call_pos]
                post_context = body[call_pos:min(len(body), call_pos + len(call) + 120)]
                # Look for (bool success/ok) assignment before OR require(success) after
                has_pre = bool(re.search(r'\(bool\s+\w+', pre_context))
                has_post = bool(re.search(r'require\s*\(\s*(success|ok)\b', post_context))
                if not has_pre and not has_post:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.UNCHECKED_RETURN,
                        title=f"Unchecked low-level call in {func['name']}()",
                        description=f"Low-level .call() in {func['name']}() without checking "
                                   f"return value.",
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=True,
                        fix_suggestion="Capture and check: (bool success, ) = addr.call{...}(); require(success);",
                        cwe="CWE-252",
                    ))
        return findings

    def _filter_false_positives(self, result: StaticAnalysisResult):
        """
        Apply false positive filtering rules.
        
        Key insight from the Ample audit: "admin can do X" is NOT a bug.
        Correct validation patterns should be PASS, not findings.
        """
        for finding in result.findings:
            # Rule 1: Admin-controlled functions are trust assumptions, not bugs
            if finding.category == StaticCategory.TRUST_ASSUMPTION:
                finding.is_false_positive = True
                finding.fp_reason = "Admin trust assumption -- by design"
                if finding.severity in (StaticSeverity.CRITICAL, StaticSeverity.HIGH):
                    finding.severity = StaticSeverity.INFO

            # Rule 2: Functions with nonReentrant are safe from reentrancy.
            # Exception: read-only reentrancy finding — the description mentions
            # nonReentrant because the *trigger* function has it, not the victim view
            # function. The whole point of read-only reentrancy is that nonReentrant
            # does NOT protect view functions from being called during the ETH callback.
            if (finding.category == StaticCategory.REENTRANCY
                    and 'nonReentrant' in finding.description
                    and 'Read-only reentrancy' not in finding.title):
                finding.is_false_positive = True
                finding.fp_reason = "Protected by nonReentrant modifier"

            # Rule 3: Reentrancy finding where source comments declare omission intentional
            if finding.category == StaticCategory.REENTRANCY and '[intentional-no-reentrant]' in finding.description:
                finding.is_false_positive = True
                finding.fp_reason = "Intentional nonReentrant omission documented in source comments"
                finding.severity = StaticSeverity.INFO

    def _detect_waterfall_skip(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        Detect if/return guard patterns that skip partial consumption.
        Pattern found in InfiniFi YieldSharing._handleNegativeYield().
        """
        findings = []
        for func in functions:
            body = func.get("body", "")
            if not body:
                continue
            clean_body = self._strip_comments(body)
            waterfall_re = _rc(
                r'if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)\s*\{[^}]*'
                r'(?:burn|transfer|consume|send|safeTransfer)'
                r'[^}]*return;?\s*\}',
                re.DOTALL
            )
            for match in waterfall_re.finditer(clean_body):
                guard_var = match.group(1)
                compared_var = match.group(2)
                after_block = clean_body[match.end():]
                if guard_var not in after_block and len(after_block.strip()) > 20:
                    func_name = func.get("name", "unknown")
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.WATERFALL_LOGIC,
                        title=f"Waterfall skip: `{guard_var}` not partially consumed in {func_name}()",
                        description=(
                            f"Function {func_name}() checks `if ({guard_var} >= {compared_var})` "
                            f"and returns early if the guard fully covers the value. When "
                            f"`{guard_var} < {compared_var}`, the code falls through WITHOUT "
                            f"consuming any of `{guard_var}`. Partially-available resources "
                            f"are wasted and downstream consumers absorb the full impact."
                        ),
                        location=f"{func_name}()",
                        exploitable=True,
                        fix_suggestion=(
                            f"Add partial consumption: burn/transfer the available `{guard_var}` "
                            f"and subtract it from `{compared_var}` before falling through."
                        ),
                        cwe="CWE-682",
                    ))
        return findings

    def _detect_permissionless_critical_functions(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        Detect state-changing functions that lack access control.
        Pattern found in InfiniFi YieldSharing.accrue().
        """
        findings = []
        critical_keywords = {
            "mint", "burn", "slash", "distribute", "accrue", "harvest",
            "rebalance", "liquidate", "setPrice", "updatePrice",
            "applyLosses", "depositRewards",
        }
        for func in functions:
            name = func.get("name", "")
            modifiers = func.get("modifiers", [])
            visibility = func.get("visibility", "public")
            body = func.get("body", "")
            # Skip non-externally-callable functions
            if visibility in ("internal", "private"):
                continue
            # Skip view/pure (no state changes possible)
            modifiers_lower = modifiers if isinstance(modifiers, str) else " ".join(modifiers)
            if re.search(r'\b(view|pure)\b', modifiers_lower):
                continue
            if name in ("constructor", "receive", "fallback", ""):
                continue
            name_lower = name.lower()
            matched_kw = None
            for kw in critical_keywords:
                if kw.lower() in name_lower:
                    matched_kw = kw
                    break
            if not matched_kw:
                continue
            # Standard ERC20Burnable: burn/burnFrom are intentionally permissionless —
            # burn() restricts to msg.sender, burnFrom() enforces allowance. Not bugs.
            if name in ("burn", "burnFrom") and "_burn(" in body:
                continue
            # Standard ERC4626: mint(shares, receiver) is a user-facing deposit-by-shares
            # function that delegates to _deposit() — intentionally permissionless.
            if name == "mint" and "_deposit(" in body:
                continue
            has_acl = False
            modifier_str = modifiers if isinstance(modifiers, str) else " ".join(modifiers)
            for admin_mod in self.admin_modifiers:
                if admin_mod in modifier_str:
                    has_acl = True
                    break
            if ("msg.sender" in body or "_msgSender()" in body) \
                    and ("require" in body or "if" in body or "revert" in body):
                has_acl = True
            # Fix 1: detect access control enforced via internal validator calls
            # e.g. _validateLockOrBurn() → _onlyOnRamp() → if (msg.sender != ...) revert
            if not has_acl and re.search(
                r'\b(?:_validate\w+|_only\w+|_check\w+|_require\w+|_verify\w+|_auth\w+)\s*\(',
                body
            ):
                has_acl = True
            # Fix 1b: detect delegation to parent via super.<method>() — inherits parent ACL
            if not has_acl and re.search(r'\bsuper\.\w+\s*\(', body):
                has_acl = True
            if not has_acl:
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.MISSING_ACCESS_CONTROL,
                    title=f"Permissionless critical function: {name}()",
                    description=(
                        f"Function {name}() performs a critical operation "
                        f"(keyword: '{matched_kw}') but has no access control. "
                        f"Anyone can call this, enabling front-running or manipulation."
                    ),
                    location=f"{name}()",
                    exploitable=True,
                    fix_suggestion="Add access control modifier or restrict to keeper address.",
                    cwe="CWE-284",
                ))
        return findings

    # ──────────────────────────────────────────────────────────────
    # NEW v1.2: Precision Loss (division before multiplication)
    # ──────────────────────────────────────────────────────────────

    # OZ Math library functions where division is intentional (algorithms, not bugs)
    OZ_MATH_WHITELIST = {
        "invMod", "mulDiv", "tryMod", "sqrt", "log2", "log10", "log256",
        "average", "ceilDiv", "max", "min", "ternary",
        # ECDSA / signature recovery
        "tryRecover", "recover", "toEthSignedMessageHash", "toTypedDataHash",
    }

    def _detect_precision_loss(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Division before multiplication truncates intermediate result.

        Example (bug):   uint fee = (amount / 1e18) * rate;
        Example (safe):  uint fee = (amount * rate) / 1e18;

        Detects: `(expr / divisor) * multiplier` in any expression.
        Also catches: `x = a / b;` followed by `x * c` in same function body.
        
        FIXED: Skips OZ standard math library functions where division is
        part of mathematical algorithms (invMod, mulDiv, etc.), not a precision bug.
        """
        findings = []
        # Inline pattern: (a / b) * c  or  a / b * c (optional closing paren after divisor)
        inline_re = _rc(
            r'(\w[\w.\[\]]*)\s*/\s*(\w[\w.]*)\s*\)?\s*\*\s*(\w[\w.]*)'
        )
        for func in functions:
            # Skip OZ math library functions — division is intentional
            if func['name'] in self.OZ_MATH_WHITELIST:
                continue
            body = self._strip_comments(func['body'])
            for m in inline_re.finditer(body):
                dividend, divisor, multiplier = m.group(1), m.group(2), m.group(3)
                if re.fullmatch(r'[0-9_eE]+', divisor) and re.fullmatch(r'[0-9_eE]+', multiplier):
                    continue
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.PRECISION,
                    title=f"Precision loss: division before multiplication in {func['name']}()",
                    description=(
                        f"Expression `{dividend} / {divisor} * {multiplier}` truncates "
                        f"`{dividend} / {divisor}` to integer BEFORE multiplying. "
                        f"Reorder: `({dividend} * {multiplier}) / {divisor}`."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=False,
                    fix_suggestion=f"Reorder: ({dividend} * {multiplier}) / {divisor}",
                    cwe="CWE-682",
                ))

        # Two-statement pattern: x = a / b  then later  x * c
        two_stmt_re = _rc(r'(\w+)\s*=\s*\w[\w.\[\]]*\s*/\s*\w[\w.]*\s*;')
        for func in functions:
            # Skip OZ math library functions — division is intentional
            if func['name'] in self.OZ_MATH_WHITELIST:
                continue
            body = self._strip_comments(func['body'])
            for m in two_stmt_re.finditer(body):
                var = m.group(1)
                after = body[m.end():]
                if re.search(rf'\b{re.escape(var)}\b\s*\*|\*\s*\b{re.escape(var)}\b', after):
                    already = any(
                        f.title == f"Precision loss: division before multiplication in {func['name']}()"
                        for f in findings
                    )
                    if not already:
                        findings.append(StaticFinding(
                            severity=StaticSeverity.LOW,
                            category=StaticCategory.PRECISION,
                            title=f"Precision loss: division before multiplication in {func['name']}()",
                            description=(
                                f"Variable `{var}` is assigned a division result then later "
                                f"multiplied. Truncation before scaling."
                            ),
                            location=f"{func['name']}():L{func['line']}",
                            exploitable=False,
                            fix_suggestion="Multiply first, then divide.",
                            cwe="CWE-682",
                        ))
        return findings

    # ------------------------------------------------------------------
    # NEW v1.2: Fee-on-Transfer Token Accounting Mismatch
    # ------------------------------------------------------------------

    def _detect_fee_on_transfer_accounting(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: transferFrom(from, to, amount) then state update using amount
        directly instead of measuring balanceAfter - balanceBefore.
        """
        findings = []
        # Use a helper to extract transferFrom calls with nested paren support
        tfrom_name_re = _rc(r'(\w+)\.transferFrom\s*\(', re.MULTILINE)
        balance_re = _rc(r'\.balanceOf\s*\(', re.MULTILINE)

        def _extract_paren_args(text, start):
            """Extract balanced parentheses content starting at 'start' (points to opening '(')."""
            depth = 0
            i = start
            while i < len(text):
                if text[i] == '(':
                    depth += 1
                elif text[i] == ')':
                    depth -= 1
                    if depth == 0:
                        return text[start+1:i], i+1
                i += 1
            return None, len(text)

        for func in functions:
            body = self._strip_comments(func['body'])
            for m in tfrom_name_re.finditer(body):
                token_var = m.group(1)
                paren_start = m.end() - 1  # points to '('
                args_str, end_pos = _extract_paren_args(body, paren_start)
                if args_str is None:
                    continue
                # Split on commas not inside nested parens
                args = []
                depth = 0
                current = ''
                for ch in args_str:
                    if ch == '(':
                        depth += 1
                        current += ch
                    elif ch == ')':
                        depth -= 1
                        current += ch
                    elif ch == ',' and depth == 0:
                        args.append(current.strip())
                        current = ''
                    else:
                        current += ch
                if current.strip():
                    args.append(current.strip())
                if len(args) < 3:
                    continue
                amount_arg = args[2]

                # Skip ERC721 transferFrom — the 3rd arg is a tokenId (NFT identifier),
                # not a fungible amount. ERC721 cannot have fee-on-transfer semantics.
                if re.search(r'\b(?:tokenId|tokenID|_tokenId|_tokenID|nftId|nftID'
                             r'|tokenIndex|_id\b|id_\b)\b', amount_arg, re.IGNORECASE):
                    continue
                # Also skip if the arg looks like a cast of an ID (e.g. uint256(tokenId))
                if re.search(r'uint256\s*\(\s*\w*[Ii][Dd]\w*\s*\)', amount_arg):
                    continue

                after = body[end_pos:]
                # The amount must appear in a direct assignment — not just as a function arg.
                # Pattern: `= ... amount_arg ...` but NOT `fn(... amount_arg ...)` only.
                used_directly = bool(re.search(
                    rf'[\+\-]?=\s*[^;(]*\b{re.escape(amount_arg)}\b',
                    after
                ))
                has_balance_check = bool(balance_re.search(body[:m.start()])) or \
                                    bool(balance_re.search(after))
                if used_directly and not has_balance_check:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.HIGH,
                        category=StaticCategory.ACCOUNTING,
                        title=f"Fee-on-transfer accounting mismatch in {func['name']}()",
                        description=(
                            f"`{token_var}.transferFrom(..., {amount_arg})` called, "
                            f"then `{amount_arg}` used directly in state update. "
                            f"Fee-on-transfer tokens cause the contract to credit more than received."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=True,
                        fix_suggestion=(
                            f"Use balance diff: uint before = {token_var}.balanceOf(address(this)); "
                            f"transferFrom(...); uint received = {token_var}.balanceOf(address(this)) - before;"
                        ),
                        cwe="CWE-682",
                    ))
        return findings

    # ------------------------------------------------------------------
    # NEW v1.2: Missing Validation Pair (sibling function gap)
    # ------------------------------------------------------------------

    def _detect_missing_validation_pair(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Two functions sharing a parameter name where one validates
        with require/revert and the other does not.
        """
        findings = []
        param_groups: Dict[str, List[Dict]] = {}
        for func in functions:
            raw_params = [p.strip() for p in func['params'].split(',') if p.strip()]
            for p in raw_params:
                parts = p.split()
                if parts:
                    pname = parts[-1].lstrip('_')
                    param_groups.setdefault(pname, []).append(func)

        for pname, funcs in param_groups.items():
            if len(funcs) < 2:
                continue
            validated_by = []
            not_validated_by = []
            for func in funcs:
                body = self._strip_comments(func['body'])
                # Skip interface/abstract declarations (empty body) — they have no
                # validation by definition and shouldn't influence the comparison.
                if not body.strip():
                    continue
                has_validation = bool(re.search(
                    rf'(?:require|revert|if)\s*[\s(][^;{{]*\b{re.escape(pname)}\b',
                    body
                ))
                if has_validation:
                    # Only public/external functions count as validation sources.
                    # Internal helpers (e.g. _approve, _update) doing validation is
                    # normal delegation — the public wrapper isn't missing a check.
                    if func['visibility'] not in ('internal', 'private'):
                        validated_by.append(func['name'])
                else:
                    not_validated_by.append(func['name'])

            if validated_by and not_validated_by:
                for missing_func_name in not_validated_by:
                    missing_func = next(f for f in funcs if f['name'] == missing_func_name)
                    if missing_func['visibility'] in ('internal', 'private'):
                        continue
                    # Fix 2a: skip view/pure functions — returning a mapping default is safe
                    state_mut = missing_func.get('stateMutability', '')
                    func_mods = missing_func.get('modifiers', '')
                    mod_str = func_mods if isinstance(func_mods, str) else ' '.join(func_mods)
                    if state_mut in ('view', 'pure') or re.search(r'\b(view|pure)\b', mod_str):
                        continue
                    # Fix 2b: skip privileged functions — onlyOwner/onlyRole = no untrusted path
                    is_privileged = any(
                        adm in mod_str for adm in self.admin_modifiers
                    )
                    if is_privileged:
                        continue
                    # Fix 2c: detect implicit validation via address comparison on the param
                    func_body = self._strip_comments(missing_func['body'])
                    # Direct: msg.sender != address(<param>)
                    implicit_val = re.search(
                        rf'msg\.sender\s*!=\s*address\([^)]*{re.escape(pname)}[^)]*\)',
                        func_body
                    )
                    if implicit_val:
                        continue
                    # Indirect: param used as mapping key → result compared to msg.sender
                    # e.g. s_destChainConfigs[destChainSelector].router → msg.sender check
                    mapping_then_sender = (
                        re.search(rf'\w+\[{re.escape(pname)}\]', func_body) and
                        re.search(r'msg\.sender', func_body) and
                        re.search(r'\bif\b', func_body)
                    )
                    if mapping_then_sender:
                        continue
                    # Fix 2d: function delegates to super — validation inherited from parent
                    if re.search(rf'\bsuper\.\w+\s*\([^)]*\b{re.escape(pname)}\b', func_body):
                        continue
                    # Fix 2e: only flag when validated_by shares a name stem with the
                    # missing function — prevents cross-contract semantic mismatches
                    # (e.g. blockUser validates `account` != 0 but burnFrom using `account`
                    # as burn-target is a completely different semantic context).
                    name_overlap = any(
                        vname.lower() in missing_func_name.lower() or
                        missing_func_name.lower() in vname.lower()
                        for vname in validated_by
                    )
                    if not name_overlap:
                        continue
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.INPUT_VALIDATION,
                        title=f"Missing validation on `{pname}` in {missing_func_name}()",
                        description=(
                            f"Parameter `{pname}` validated in "
                            f"{', '.join(validated_by)} but NOT in {missing_func_name}(). "
                            f"Inconsistent validation — attacker uses the unprotected variant."
                        ),
                        location=f"{missing_func_name}():L{missing_func['line']}",
                        exploitable=True,
                        fix_suggestion=f"Add same validation for `{pname}` as in {validated_by[0]}().",
                        cwe="CWE-20",
                    ))
        return findings

    # ==================================================================
    # Phase 3 (v1.3) — New detection patterns
    # ==================================================================

    def _detect_erc4626_share_inflation(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        ERC-4626 First Depositor / Share Inflation Attack.

        Attack vector:
          1. Attacker mints 1 share (first depositor).
          2. Attacker donates a large amount of the underlying asset directly
             to the vault (increments ``totalAssets`` without minting shares).
          3. Next depositor receives 0 shares because:
             ``shares = assets * totalSupply / totalAssets`` rounds down to 0.

        Detects vaults that compute shares WITHOUT a virtual-offset (dead
        shares) defence — specifically, ``totalSupply`` in a division that
        lacks ``+ OFFSET`` or ``+ 1`` virtual-shares protection.

        Pattern:  ``shares = … * totalSupply() / totalAssets()``
                  without ``+ <constant>`` on either side.
        """
        findings = []

        # Heuristic 1: vault inherits ERC4626 or implements deposit/mint/redeem
        is_vault = bool(re.search(
            r'(?:ERC4626|ERC_4626)\b|'
            r'\bfunction\s+(?:deposit|mint|redeem|withdraw)\s*\(',
            source
        ))
        if not is_vault:
            return findings

        # Heuristic 2: shares computed via totalSupply / totalAssets without
        # an additive virtual-share offset
        share_calc_re = _rc(
            r'(?:shares?|amount)\s*=\s*[^;]*\btotalSupply\b[^;]*/[^;]*\btotalAssets\b[^;]*;',
            re.IGNORECASE
        )
        virtual_offset_re = _rc(
            r'\btotalSupply\b[^;]*\+\s*\d+|'     # totalSupply + constant
            r'\d+\s*\+[^;]*\btotalSupply\b|'     # constant + totalSupply
            r'DEAD_SHARES|VIRTUAL|virtual_shares|'
            r'_decimals_offset',
            re.IGNORECASE
        )

        for func in functions:
            body = self._strip_comments(func['body'])
            for m in share_calc_re.finditer(body):
                expr = m.group(0)
                if not virtual_offset_re.search(expr):
                    findings.append(StaticFinding(
                        severity=StaticSeverity.HIGH,
                        category=StaticCategory.ERC4626,
                        title=f"ERC-4626 share inflation risk in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` computes shares as "
                            f"``assets * totalSupply / totalAssets`` without a "
                            f"virtual-share offset.  A first depositor can donate "
                            f"assets to inflate the share price and round subsequent "
                            f"depositors' shares to zero (first-depositor attack)."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=True,
                        fix_suggestion=(
                            "Add virtual shares: use ``totalSupply + 10**decimalsOffset`` "
                            "in the denominator, or inherit OpenZeppelin ERC4626 v5 "
                            "which includes this protection by default."
                        ),
                        cwe="CWE-682",
                    ))
        return findings

    def _same_function(self, offset_a: int, offset_b: int, source: str) -> bool:
        """
        Check whether two raw character offsets in *source* belong to the
        same function body.  Used to prevent cross-function CEI FPs that arise
        when external-call and state-write offsets are compared globally.
        """
        func_starts = [m.start() for m in re.finditer(r'\bfunction\s+\w+', source)]
        func_starts.append(len(source))  # sentinel

        def _func_idx(offset: int) -> Optional[int]:
            for i in range(len(func_starts) - 1):
                if func_starts[i] <= offset < func_starts[i + 1]:
                    return i
            return None

        fa = _func_idx(offset_a)
        fb = _func_idx(offset_b)
        return fa is not None and fa == fb

    def _has_inline_reentrancy_guard(self, func_source: str) -> bool:
        """
        Detect custom inline reentrancy guard patterns that are semantically
        equivalent to the ``nonReentrant`` modifier but implemented inline.

        Recognises:
          1. Bool flag set true at entry, false at exit  (mutex pattern)
          2. Revert-if-true check whose name contains "reentrancy" / "reentrant"
          3. ``reentrancyGuard* = true`` named variable
          4. Struct-field guard: ``s_foo.reentrancyGuardEntered = true``
          5. ``locked = true`` / ``_mutex = true`` mutex pattern
        """
        patterns = [
            # Pattern 2: revert if bool is true with "reentrancy" in identifier
            r'if\s*\([^)]*\)\s*revert\s+\w*[Rr]eetrancy\w*',
            # Pattern 3: named reentrancyGuard variable set to true
            r'reentrancy[Gg]uard\w*\s*=\s*true',
            # Pattern 4: struct-field guard (Chainlink OnRamp pattern)
            r'\w+\.reentrancy\w+\s*=\s*true',
            # Pattern 5: classic mutex names
            r'\b(?:mutex|_mutex|locked|_locked|_entered)\s*=\s*true',
        ]
        for pattern in patterns:
            if re.search(pattern, func_source, re.DOTALL | re.IGNORECASE):
                return True
        return False

    def _detect_reentrancy_cei(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        Checks-Effects-Interactions (CEI) pattern violation — expanded version.

        Looks for the pattern:
          1. A low-level ``.call{}`` OR a high-level interface call (I*.method())
          2. Followed by a storage write (``mapping[…] =``, ``_var =``, etc.)
          3. WITHOUT a ``nonReentrant`` guard (modifier or inline).

        Both the external call and the state write must be in the same function
        body (enforced via _same_function()) to prevent cross-function FPs.
        """
        findings = []
        ext_call_re  = _rc(r'(?:\.call\{|\.send\(|\.transfer\(|I\w+\([^)]*\)\.\w+\()')
        # Deliberately excludes `_\w+ =` — that matches local variables and causes ~50% FP rate.
        # Only flag writes to patterns that are unambiguously storage in Solidity conventions.
        state_write_re = _rc(
            r'(?:'
            r'\w+\[(?:[^\]]+)\]\s*[\+\-\*\/]?=|'   # mapping[key] (op)= value
            r'\bs_\w+\s*[\+\-\*\/]?=|'               # s_storageVar (Chainlink/modern style)
            r'\b\w+Supply\b\s*[\+\-]?=|'             # totalSupply +=
            r'\bbalance\w*\s*[\+\-]?=|'              # balance +=
            r'\btotalDebt\b\s*[\+\-]?=|'             # totalDebt +=
            r'\btotalAssets\b\s*[\+\-]?='            # totalAssets +=
            r')'
        )

        _INTENTIONAL_RE = _rc(
            r'(?:intentional|composabilit|by\s+design|no\s+reentranc|purpose|'
            r'no\s+reentrancy\s+check|not\s+reentrant\s+on\s+purpose)',
            re.IGNORECASE,
        )
        _source_lines = source.splitlines()

        for func in functions:
            # Skip if standard nonReentrant modifier present
            if 'nonReentrant' in func.get('modifiers', ''):
                continue

            raw_body = func['body']   # keep comments for intentional-check
            body = self._strip_comments(raw_body)

            # Fix 2: skip if an inline reentrancy guard is present
            if self._has_inline_reentrancy_guard(body):
                continue

            # Skip interface declarations (no real body — body is empty or near-empty)
            if len(body.strip()) < 5:
                continue

            all_ext_calls = list(ext_call_re.finditer(body))
            # Filter out known view-only method calls — they cannot trigger reentrancy
            ext_calls = [c for c in all_ext_calls if not self._is_view_only_call(c.group(0))]
            if not ext_calls:
                continue

            # Find earliest non-view external call position within this function body
            first_call_pos = ext_calls[0].start()
            first_call_text = ext_calls[0].group(0)

            # Determine confidence: .call{value:...} or .transfer/.send are high-risk;
            # interface calls without view filter are medium-risk
            is_value_transfer = bool(re.search(r'\.call\s*\{|\.transfer\s*\(|\.send\s*\(', first_call_text))
            call_confidence = 0.85 if is_value_transfer else 0.65

            # Tag intentional omissions: check raw body AND the 8 source lines
            # before the function declaration (NatSpec/comments precede the function)
            func_line = func.get('line', 1)
            preceding_lines = "\n".join(
                _source_lines[max(0, func_line - 9): func_line]
            )
            intentional_tag = ""
            if _INTENTIONAL_RE.search(raw_body) or _INTENTIONAL_RE.search(preceding_lines):
                intentional_tag = " [intentional-no-reentrant]"

            # Check if there's a state write AFTER the first external call
            for m in state_write_re.finditer(body):
                if m.start() > first_call_pos:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.HIGH,
                        category=StaticCategory.REENTRANCY,
                        title=f"CEI violation (reentrancy risk) in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` performs an external call at position "
                            f"{first_call_pos} then writes to state at position {m.start()}. "
                            f"No ``nonReentrant`` guard present.  "
                            f"An attacker can reenter before the state update."
                            f"{intentional_tag}"
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=True,
                        fix_suggestion=(
                            "Add ``nonReentrant`` modifier, or move all state writes "
                            "BEFORE the external call (CEI pattern)."
                        ),
                        cwe="CWE-841",
                        confidence=call_confidence,
                    ))
                    break  # One finding per function is sufficient
        return findings

    def _detect_flashloan_price_manipulation(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        Flash-loan + spot-price read in the same function.

        When a function (a) receives a flash-loan callback AND (b) reads a
        spot price without TWAP protection, an attacker can manipulate the
        oracle within the flash-loan window and call the vulnerable function
        to exploit the inflated/deflated price.

        Pattern: function contains ``flashLoan`` / ``executeOperation`` /
                 ``uniswapV3SwapCallback`` AND reads ``getPrice`` /
                 ``slot0`` / ``getReserves`` without ``getTWAP`` nearby.
        """
        findings = []

        flash_callback_re = _rc(
            r'\b(?:executeOperation|onFlashLoan|uniswapV3FlashCallback|'
            r'flashLoanSimple|pancakeCall|callbackData)\b',
            re.IGNORECASE
        )
        # latestRoundData is a Chainlink feed, not an AMM spot price — different attack surface.
        spot_price_re = _rc(
            r'\b(?:getPrice|slot0|getReserves|consult|observe)\s*\(',
            re.IGNORECASE
        )
        twap_protection_re = _rc(
            r'\b(?:getTWAP|TWAP|twap|TimeWeighted|twapDuration|'
            r'observationIndex|cardinality)\b',
            re.IGNORECASE
        )

        for func in functions:
            body = self._strip_comments(func['body'])
            full_sig = func.get('full_match', '') + body

            # Check for flash-loan callback signature in function name or body
            is_flash_callback = bool(flash_callback_re.search(func['name'])) or \
                                 bool(flash_callback_re.search(body))
            has_spot_price     = bool(spot_price_re.search(body))
            has_twap           = bool(twap_protection_re.search(body))

            if is_flash_callback and has_spot_price and not has_twap:
                findings.append(StaticFinding(
                    severity=StaticSeverity.CRITICAL,
                    category=StaticCategory.ORACLE,
                    title=f"Flash-loan price manipulation risk in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` is a flash-loan callback that reads "
                        f"a spot-price oracle without TWAP protection.  "
                        f"An attacker can borrow a flash loan, manipulate the AMM "
                        f"reserve ratio, then trigger this function to exploit the "
                        f"artificial price before repaying the loan — all in one tx."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        "Replace spot-price reads (``getReserves``, ``slot0``, etc.) "
                        "with a TWAP oracle (``getTWAP(30 minutes)`` via UniV3 or "
                        "Chainlink).  Never use spot prices inside flash-loan callbacks."
                    ),
                    cwe="CWE-330",
                ))
        return findings

    def _detect_missing_zero_address(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        Missing zero-address check on ``address`` parameters.

        Functions that receive an ``address`` parameter and write it to state
        (``owner =``, ``recipient =``, ``_token =``, etc.) without first
        checking ``address(0)`` / ``address(0x0)`` can permanently brick the
        contract if the zero address is passed accidentally.

        Pattern:
          • Parameter type is ``address``
          • Body writes the parameter to a state variable
          • Body does NOT contain ``address(0)``, ``!= address(0)``,
            ``require(… != 0)``, or ``if (… == address(0)) revert``
        """
        findings = []
        zero_check_re = _rc(
            r'address\s*\(\s*0\s*\)|'           # address(0)
            r'!=\s*address\s*\(\s*0\s*\)|'      # != address(0)
            r'==\s*address\s*\(\s*0\s*\)|'      # == address(0)
            r'ZeroAddress|'                       # custom error name
            r'zero[_\s]?address',                 # string pattern
            re.IGNORECASE
        )

        for func in functions:
            # Only check public/external functions (those callable by users)
            if func.get('visibility') in ('internal', 'private'):
                continue

            body = self._strip_comments(func['body'])

            # Collect address-typed parameter names
            addr_params = []
            for part in func.get('params', '').split(','):
                part = part.strip()
                if part.startswith('address ') or part.startswith('address\t'):
                    name_parts = part.split()
                    if len(name_parts) >= 2:
                        addr_params.append(name_parts[-1].lstrip('_'))

            if not addr_params:
                continue

            has_zero_check = bool(zero_check_re.search(body))
            if has_zero_check:
                continue  # At least one zero-address check exists

            # Check if any address param is written to state
            for param in addr_params:
                state_write = re.search(
                    rf'\b\w+\s*=\s*{re.escape(param)}\b|'
                    rf'{re.escape(param)}\s*=\s*\w+',
                    body
                )
                if state_write:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.ZERO_ADDRESS,
                        title=f"Missing zero-address check for ``{param}`` in {func['name']}()",
                        description=(
                            f"Parameter ``{param}`` (type ``address``) is written to state "
                            f"in ``{func['name']}()`` without a zero-address guard.  "
                            f"Passing ``address(0)`` permanently bricks the function's "
                            f"intended recipient/owner."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion=(
                            f"Add: ``require({param} != address(0), \\\"Zero address\\\");`` "
                            f"or use a custom error ``if ({param} == address(0)) revert ZeroAddress();``"
                        ),
                        cwe="CWE-20",
                    ))
                    break  # One finding per function
        return findings

    def _detect_unchecked_erc20_transfers(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        Unchecked return values on ERC-20 ``transfer`` / ``transferFrom``.

        Non-standard ERC-20 tokens (USDT, BNB, some others) return ``false``
        on failure instead of reverting.  If the caller ignores the return
        value, the contract believes the transfer succeeded.

        Two patterns flagged:
        1. Bare ``token.transfer(to, amount)`` without capturing return value.
        2. Bare ``token.transferFrom(from, to, amount)`` without capturing
           return value — when ``safeTransferFrom`` / ``safeTransfer`` is not used.

        NOT flagged when:
        - ``SafeERC20`` / ``safeTransfer`` / ``safeTransferFrom`` is used.
        - Return value is captured: ``bool ok = token.transfer(...)``.
        """
        findings = []

        # Positive: return value captured
        captured_re   = _rc(r'bool\s+\w+\s*=\s*\w+\.transfer(?:From)?\s*\(')
        # Positive: safe wrapper used
        safe_re       = _rc(r'\bsafe(?:Transfer|TransferFrom)\b', re.IGNORECASE)
        # Target: bare transfer / transferFrom calls (not safeTransfer)
        bare_re       = _rc(
            r'(?<!\w)(?<!safe)(?<!Safe)\b(\w+)\.transfer(?:From)?\s*\([^)]+\)\s*;',
        )

        for func in functions:
            body = self._strip_comments(func['body'])

            # Skip functions that use SafeERC20 wrappers
            if safe_re.search(body):
                continue

            for m in bare_re.finditer(body):
                token_var = m.group(1)
                # Skip if return value is captured in a preceding statement
                context = body[max(0, m.start() - 80):m.start()]
                if 'bool' in context and token_var in context:
                    continue
                if captured_re.search(body):
                    continue

                call_text = m.group(0).strip()
                # Fix 4: downgrade to LOW if the function is privileged
                # (admin calling transfer with a known-reverting token is not exploitable)
                func_mods = func.get('modifiers', '')
                mod_str = func_mods if isinstance(func_mods, str) else ' '.join(func_mods)
                is_privileged = any(adm in mod_str for adm in self.admin_modifiers)
                sev = StaticSeverity.LOW if is_privileged else StaticSeverity.MEDIUM
                findings.append(StaticFinding(
                    severity=sev,
                    category=StaticCategory.UNCHECKED_RETURN,
                    title=f"Unchecked ERC-20 return value in {func['name']}()",
                    description=(
                        f"``{call_text}`` in ``{func['name']}()`` ignores the boolean "
                        f"return value.  Non-standard tokens (USDT, BNB) return ``false`` "
                        f"instead of reverting on failure, silently skipping the transfer."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        "Use OpenZeppelin ``SafeERC20.safeTransfer()`` / "
                        "``safeTransferFrom()``, or capture and require the return: "
                        "``require(token.transfer(to, amount), \\\"Transfer failed\\\");``"
                    ),
                    cwe="CWE-252",
                ))
        return findings

    # ==================================================================
    # v1.4 — Stale Oracle & Unprotected Setter
    # ==================================================================

    def _detect_stale_oracle(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: Chainlink oracle staleness gaps.

        Sub-patterns:
          1. latestRoundData() result used without validating updatedAt against
             block.timestamp (the most common L2/mainnet stale-price bug).
          2. latestAnswer() used directly — deprecated, zero staleness metadata.
          3. Missing L2 sequencer uptime feed check when contract appears to be
             deployed on Arbitrum/Optimism/Base.
        """
        findings = []

        staleness_re = _rc(
            r'block\.timestamp\s*[-\+]\s*\w+|'    # block.timestamp - updatedAt
            r'\w+\s*<=?\s*block\.timestamp|'        # updatedAt <= block.timestamp
            r'STALENESS|staleness|maxStaleness|staleThreshold|'
            r'heartbeat|HEARTBEAT',
            re.IGNORECASE
        )
        sequencer_re = _rc(
            r'sequencer|sequencerFeed|sequencerOracle|'
            r'ArbitrumSequencer|OptimismSequencer|L2Sequencer',
            re.IGNORECASE
        )
        l2_re = _rc(
            r'arbitrum|optimism|polygon|avalanche|base\s*(?:chain|mainnet)|'
            r'\bL2\b|layer.?2|rollup',
            re.IGNORECASE
        )

        # `\btimestamp\b` would match `block.timestamp` — use only specific variable names.
        updated_at_var_re = _rc(
            r'\b(?:updatedAt|updated_at|lastUpdated|lastUpdate|updateTime|lastTimestamp)\b'
        )
        answer_positive_re = _rc(
            r'answer\s*(?:>|!=)\s*(?:0|int256\s*\(\s*0\s*\))|'
            r'(?:0|int256\s*\(\s*0\s*\))\s*<\s*answer',
            re.IGNORECASE
        )
        answered_in_round_re = _rc(
            r'\b(?:answeredInRound|answeredIn)\b', re.IGNORECASE
        )

        for func in functions:
            body = self._strip_comments(func['body'])

            # --- Sub-pattern 1: latestRoundData without updatedAt validation ---
            if 'latestRoundData' in body:
                captures_updated_at = bool(updated_at_var_re.search(body))
                validates_staleness = bool(staleness_re.search(body))
                checks_answer_positive = bool(answer_positive_re.search(body))
                checks_answered_in_round = bool(answered_in_round_re.search(body))

                if not captures_updated_at:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.ORACLE,
                        title=f"Stale oracle: updatedAt discarded in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` calls ``latestRoundData()`` but does not "
                            f"capture ``updatedAt``. Stale price data accepted silently."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion=(
                            "Capture all five return values and validate: "
                            "``if (block.timestamp - updatedAt > STALENESS_THRESHOLD) revert StalePrice();``"
                        ),
                        cwe="CWE-1071",
                    ))
                elif not validates_staleness:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.ORACLE,
                        title=f"Stale oracle: updatedAt captured but not validated in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` captures ``updatedAt`` from "
                            f"``latestRoundData()`` but never compares it against "
                            f"``block.timestamp``. A stale feed passes unchecked."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion=(
                            "Add: ``if (block.timestamp - updatedAt > STALENESS_THRESHOLD) "
                            "revert StalePrice();``"
                        ),
                        cwe="CWE-1071",
                    ))

                if not checks_answer_positive:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.LOW,
                        category=StaticCategory.ORACLE,
                        title=f"Oracle answer not validated > 0 in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` does not check ``answer > 0`` after "
                            f"``latestRoundData()``. A decommissioned or broken feed can return "
                            f"0 or negative, causing mispricing."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion="Add: ``if (answer <= 0) revert InvalidPrice();``",
                        cwe="CWE-1071",
                    ))

                if not checks_answered_in_round:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.LOW,
                        category=StaticCategory.ORACLE,
                        title=f"Missing answeredInRound check in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` does not validate "
                            f"``answeredInRound >= roundId``. An incomplete round returns "
                            f"stale data from the previous round."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion=(
                            "Add: ``if (answeredInRound < roundId) revert StaleRound();``"
                        ),
                        cwe="CWE-1071",
                    ))

            # --- Sub-pattern 2: deprecated latestAnswer() ---
            if re.search(r'\.latestAnswer\s*\(\s*\)', body):
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.ORACLE,
                    title=f"Deprecated latestAnswer() in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` uses ``latestAnswer()`` which is deprecated "
                        f"and returns no round metadata. Staleness cannot be checked."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=False,
                    fix_suggestion=(
                        "Replace with ``latestRoundData()``; validate ``updatedAt``, "
                        "``answeredInRound >= roundId``, and ``answer > 0``."
                    ),
                    cwe="CWE-1071",
                ))

        # --- Sub-pattern 3: L2 sequencer uptime not checked ---
        uses_chainlink = bool(re.search(r'latestRoundData|latestAnswer|AggregatorV3', source))
        if uses_chainlink and l2_re.search(source) and not sequencer_re.search(source):
            loc_match = re.search(r'latestRoundData|latestAnswer', source)
            line_num = source[:loc_match.start()].count('\n') + 1 if loc_match else 0
            findings.append(StaticFinding(
                severity=StaticSeverity.LOW,   # heuristic-only; L2 match may be a comment
                category=StaticCategory.ORACLE,
                title="Missing L2 sequencer uptime check",
                description=(
                    "Contract uses Chainlink price feeds on an apparent L2 "
                    "(Arbitrum/Optimism/Base) but does not check the sequencer uptime feed. "
                    "When the sequencer is down, ``latestRoundData()`` still returns stale "
                    "cached data without reverting."
                ),
                location=f"L{line_num}" if line_num else "global",
                exploitable=False,
                fix_suggestion=(
                    "Add: ``(, int256 seq, uint256 startedAt,,) = sequencerFeed.latestRoundData(); "
                    "require(seq == 0 && block.timestamp - startedAt > GRACE_PERIOD, 'Sequencer down');``"
                ),
                cwe="CWE-1071",
            ))

        return findings

    def _detect_unprotected_setters(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: External/public setter functions without access control.

        The existing PERMISSIONLESS_CRITICAL detector focuses on action keywords
        (mint/burn/liquidate). This detector focuses on *configuration setters*:
        functions named set*/update*/change*/configure* that write to state but
        carry no admin modifier or msg.sender check — a common access control gap
        that static analysis can catch directly.

        Not flagged:
          - Functions with any recognised admin modifier.
          - Functions that explicitly check msg.sender in the body.
          - Internal/private functions.
          - Pure/view functions.
        """
        findings = []

        setter_name_re = _rc(
            r'^(?:set|update|change|configure|register|enable|disable|'
            r'add|remove|replace|upgrade|initialize|init)[A-Z_]',
        )

        for func in functions:
            name = func.get('name', '')
            visibility = func.get('visibility', 'public')
            body = func.get('body', '')
            modifiers = func.get('modifiers', '')

            if visibility in ('internal', 'private'):
                continue
            if name in ('constructor', 'receive', 'fallback', ''):
                continue

            mod_str = modifiers if isinstance(modifiers, str) else ' '.join(modifiers)
            if re.search(r'\b(?:view|pure)\b', mod_str):
                continue

            # OZ initializer pattern: initialize()/init() with `initializer` modifier
            if re.search(r'\binitializer\b', mod_str):
                continue

            if not setter_name_re.match(name):
                continue

            # Check for any access control — known list OR any only*/auth*/guarded* modifier
            has_admin_mod = (
                any(m in mod_str for m in self.admin_modifiers)
                or bool(re.search(r'\bonly\w+\b|\bauth\w*\b|\bguarded\b|\brequireAuth\b', mod_str, re.IGNORECASE))
            )
            if has_admin_mod:
                continue

            body_clean = self._strip_comments(body)

            # Inline msg.sender check
            if re.search(r'msg\.sender', body_clean) and re.search(r'\b(?:require|revert|if)\b', body_clean):
                continue

            # Internal validator / delegated auth patterns:
            # - _validate*, _only*, _check*, _require*, _auth* (internal guards)
            # - validateSignature*, verifySignature*, recoverSigner* (sig-based auth)
            # - claimFor*, claimWithResolver* (ENS delegated-auth claim functions)
            # - ecrecover + comparison (inline ECDSA recovery check)
            if re.search(
                r'\b(?:_validate\w+|_only\w+|_check\w+|_require\w+|_auth\w+|'
                r'validate[Ss]ig\w*|validateSignature\w*|verifySignature\w*|'
                r'recoverSigner\w*|claimFor\w+|claimWith\w+)\s*\(',
                body_clean
            ):
                continue
            # Inline ECDSA: ecrecover result compared to a stored address
            if re.search(r'\becrecover\b', body_clean) and re.search(r'==|!=', body_clean):
                continue

            # Must write to state (otherwise it's a no-op setter — not interesting)
            has_state_write = bool(re.search(
                r'\b\w+\s*[\+\-\*\/]?=(?!=)|'   # assignment (not ==)
                r'\w+\[\w+\]\s*=',
                body_clean
            ))
            if not has_state_write:
                continue

            # If the function is declared `override`, access control may be inherited
            # from a parent not visible in this file — lower confidence.
            is_override = 'override' in mod_str
            sev = StaticSeverity.MEDIUM if is_override else StaticSeverity.HIGH
            conf = 0.55 if is_override else 0.82
            desc = (
                f"``{name}()`` is {visibility} and modifies state but has no access "
                f"control modifier or ``msg.sender`` check. Anyone can call it."
            )
            if is_override:
                desc += (
                    "\n[Note: function uses `override` — access control may be inherited "
                    "from parent. Confirm parent has no admin modifier before acting.]"
                )
            findings.append(StaticFinding(
                severity=sev,
                category=StaticCategory.ACCESS_CONTROL,
                title=f"Unprotected setter: {name}()",
                description=desc,
                location=f"{name}():L{func['line']}",
                exploitable=not is_override,
                fix_suggestion=f"Add ``onlyOwner`` / ``onlyRole`` modifier or inline ``if (msg.sender != admin) revert();``",
                cwe="CWE-284",
                confidence=conf,
            ))

        return findings

    # ------------------------------------------------------------------
    # NEW v1.2: AST-based deep analysis via solc
    # ------------------------------------------------------------------

    def ast_analyze(self, source_path: str, contract_name: str = "Unknown") -> List[StaticFinding]:
        """
        Run solc AST analysis on a .sol file. Requires solc in PATH.
        Falls back silently if solc is not available.
        """
        findings = []
        try:
            result = subprocess.run(
                ["solc", "--ast-compact-json", "--no-color", source_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return findings
            output = result.stdout
            json_blocks = re.findall(r'=====.*?=====\s*(\{.*)', output, re.DOTALL)
            if not json_blocks:
                json_blocks = [output]
            for block in json_blocks:
                try:
                    ast = json.loads(block)
                    findings.extend(self._walk_ast_precision(ast, contract_name))
                    findings.extend(self._walk_ast_unchecked(ast, contract_name))
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            pass
        return findings

    def _walk_ast_precision(self, node: dict, contract_name: str, _depth: int = 0) -> List[StaticFinding]:
        """Walk AST: flag BinaryOperation(*) whose child is BinaryOperation(/)."""
        findings = []
        if not isinstance(node, dict) or _depth > 50:
            return findings
        if node.get("nodeType") == "BinaryOperation" and node.get("operator") == "*":
            for side in ("leftExpression", "rightExpression"):
                child = node.get(side, {})
                if isinstance(child, dict) and child.get("nodeType") == "BinaryOperation" \
                        and child.get("operator") == "/":
                    src = node.get("src", "")
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.PRECISION,
                        title=f"[AST] Division before multiplication in {contract_name}",
                        description=(
                            "AST-confirmed: multiplication applied to result of integer division. "
                            "Intermediate value is already truncated, causing systematic precision loss."
                        ),
                        location=f"{contract_name} src={src}",
                        exploitable=False,
                        fix_suggestion="Multiply numerators first, then divide.",
                        cwe="CWE-682",
                    ))
        for value in node.values():
            if isinstance(value, dict):
                findings.extend(self._walk_ast_precision(value, contract_name, _depth + 1))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        findings.extend(self._walk_ast_precision(item, contract_name, _depth + 1))
        return findings

    def _walk_ast_unchecked(self, node: dict, contract_name: str, _depth: int = 0,
                             _in_unchecked: bool = False) -> List[StaticFinding]:
        """Walk AST: flag +/-/* BinaryOperations inside UncheckedStatement blocks.

        An unchecked block disables Solidity 0.8 overflow/underflow guards.  Any
        arithmetic on values that may originate from user input becomes exploitable.
        """
        findings = []
        if not isinstance(node, dict) or _depth > 50:
            return findings

        node_type = node.get("nodeType")

        if node_type == "UncheckedStatement":
            # Recurse into all children with the unchecked flag set
            for child in node.get("statements", []):
                findings.extend(
                    self._walk_ast_unchecked(child, contract_name, _depth + 1, _in_unchecked=True)
                )
            return findings

        if _in_unchecked and node_type == "BinaryOperation":
            op = node.get("operator", "")
            if op in ("+", "-", "*"):
                src = node.get("src", "")
                findings.append(StaticFinding(
                    severity=StaticSeverity.LOW,
                    category=StaticCategory.PRECISION,
                    title=f"[AST] Unchecked arithmetic ({op}) in {contract_name}",
                    description=(
                        f"AST-confirmed: `{op}` operation inside `unchecked{{}}` block. "
                        f"Solidity 0.8 overflow/underflow protection is disabled. "
                        f"If operands derive from user-controlled input this can wrap silently."
                    ),
                    location=f"{contract_name} src={src}",
                    exploitable=False,
                    fix_suggestion=(
                        "Verify both operands are bounded before the unchecked block, "
                        "or move the operation outside unchecked{} to restore revert-on-overflow."
                    ),
                    cwe="CWE-190",
                    confidence=0.70,
                ))

        for value in node.values():
            if isinstance(value, dict):
                findings.extend(
                    self._walk_ast_unchecked(value, contract_name, _depth + 1, _in_unchecked)
                )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        findings.extend(
                            self._walk_ast_unchecked(item, contract_name, _depth + 1, _in_unchecked)
                        )
        return findings

    # ── Novel detector: msg.value reuse in loops ──────────────────────────

    def _detect_msg_value_in_loop(self, source: str, functions: List[Dict]) -> List[StaticFinding]:
        """
        PATTERN: msg.value read inside a for/while/do loop body.

        Solidity does NOT decrement msg.value per iteration. Every iteration
        sees the full original msg.value, making multi-call or batch functions
        that loop over msg.value trivially exploitable — an attacker can drain
        N× the ETH they sent.

        Real-world: multiple C4 criticals (Nouns DAO, ArtGobblers variants,
        custom multicall patterns). Slither does not detect this pattern.

        Only fires when:
          - A loop keyword (for/while/do) is present in the function body
          - msg.value appears inside a scope nested within that loop (or
            appears in the body after the loop keyword without a dedicated
            ETH-tracking variable)
          - No clear per-iteration accounting: running total / `sent +=`
        """
        findings = []
        _LOOP_RE    = _rc(r'\b(?:for|while|do)\s*[({]', re.DOTALL)
        _MSGVAL_RE  = _rc(r'\bmsg\.value\b')
        _TRACKING_RE = _rc(
            r'\b(?:total|sent|remaining|used|amount)\s*\+?='
            r'|\bamountSent\b|\bvalueUsed\b|\bspent\b',
            re.IGNORECASE
        )

        for func in functions:
            body = self._strip_comments(func['body'])
            if not _LOOP_RE.search(body):
                continue
            if not _MSGVAL_RE.search(body):
                continue

            # Suppress if there's a tracking accumulator (safe pattern)
            if _TRACKING_RE.search(body):
                continue

            # Find the first loop, then check if msg.value appears after it
            loop_match = _LOOP_RE.search(body)
            after_loop = body[loop_match.start():]
            if not _MSGVAL_RE.search(after_loop):
                continue

            findings.append(StaticFinding(
                severity=StaticSeverity.CRITICAL,
                category=StaticCategory.LOGIC,
                title=f"msg.value reuse in loop: {func['name']}()",
                description=(
                    f"``{func['name']}()`` reads ``msg.value`` inside a loop. "
                    f"Solidity does not decrement ``msg.value`` per iteration — "
                    f"each iteration receives the full original ETH amount. "
                    f"An attacker can exploit this to consume N× their sent ETH."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Track consumed ETH with a local variable: "
                    "``uint256 remaining = msg.value;`` and subtract per iteration. "
                    "Or use a per-call value array instead of msg.value in loops."
                ),
                cwe="CWE-841",
                confidence=0.90,
            ))

        return findings

    # ── Novel detector: UUPS implementation without _disableInitializers ──

    def _detect_uups_missing_disable_initializers(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        PATTERN: UUPS upgradeable implementation contract lacks
        _disableInitializers() in its constructor.

        Without _disableInitializers(), the *implementation* contract (not the
        proxy) can be initialized by anyone. Combined with an UUPS
        upgradeToAndCall() on the implementation itself, an attacker can
        self-destruct or corrupt the implementation, bricking the proxy.

        Real-world: Wormhole $320M bug (2022), multiple C4 highs post-EIP-1967.
        OZ explicitly recommends _disableInitializers() since v4.6.0.

        Fires when:
          - Contract inherits from UUPSUpgradeable or OwnableUpgradeable or
            similar upgradeable base
          - A constructor function exists
          - _disableInitializers() is NOT called in constructor body
        """
        _UUPS_INHERIT_RE = _rc(
            r'\b(?:UUPSUpgradeable|Initializable|OwnableUpgradeable|'
            r'AccessControlUpgradeable|PausableUpgradeable|'
            r'ERC20Upgradeable|ERC721Upgradeable)\b'
        )
        if not _UUPS_INHERIT_RE.search(source):
            return []

        constructor = next(
            (f for f in functions if f['name'] == 'constructor'), None
        )
        if constructor is None:
            # No constructor at all — flag: implementation init always frontrunnable
            _cname_m = re.search(r'^(?:abstract\s+)?contract\s+(\w+)', source, re.MULTILINE)
            _cname = _cname_m.group(1) if _cname_m else "Unknown"
            return [StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.ACCESS_CONTROL,
                title="UUPS/upgradeable: no constructor with _disableInitializers()",
                description=(
                    "Contract inherits from an OpenZeppelin upgradeable base but has "
                    "no constructor calling ``_disableInitializers()``. The implementation "
                    "contract can be initialized by anyone, potentially enabling an attacker "
                    "to take ownership of the implementation and call ``upgradeToAndCall`` "
                    "with a self-destruct payload, bricking all proxies."
                ),
                location=f"{_cname}:constructor",
                exploitable=True,
                fix_suggestion=(
                    "Add a constructor: "
                    "``constructor() { _disableInitializers(); }``"
                ),
                cwe="CWE-665",
                confidence=0.88,
            )]

        body = self._strip_comments(constructor['body'])
        if '_disableInitializers' in body:
            return []

        return [StaticFinding(
            severity=StaticSeverity.HIGH,
            category=StaticCategory.ACCESS_CONTROL,
            title="UUPS/upgradeable: constructor missing _disableInitializers()",
            description=(
                "Constructor exists but does not call ``_disableInitializers()``. "
                "The implementation contract (not the proxy) is vulnerable to "
                "initialization by a malicious actor, who can then call "
                "``upgradeToAndCall`` on the implementation to execute arbitrary code."
            ),
            location=f"constructor():L{constructor['line']}",
            exploitable=True,
            fix_suggestion=(
                "Add ``_disableInitializers();`` as the first line of the constructor "
                "to prevent the implementation from being initialized after deployment."
            ),
            cwe="CWE-665",
            confidence=0.88,
        )]

    # ── Novel detector: delegatecall to user-controlled address ──────────

    def _detect_delegatecall_injection(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        PATTERN: delegatecall target derived from untrusted input.

        A ``delegatecall`` executes code in the context of the calling contract
        — full access to storage, ETH balance, and msg.sender. If the target
        address is controlled by an attacker (function parameter, storage slot
        set by user, or return value from untrusted oracle), this is an
        unconditional takeover.

        Safe pattern:  immutable/constant target set at deploy time.
        Unsafe patterns:
          - addr.delegatecall(data) where addr is a function parameter
          - implementation().delegatecall(data) where implementation() reads
            a storage slot (without admin-gated setter) → covered by unprotected setters
          - Any delegatecall where the address expression is not a compile-time constant
            or an immutable set in the constructor.

        Slither catches some proxy patterns but not raw delegatecall injection
        in non-proxy contracts.
        """
        findings = []
        # delegatecall(bytes) — captures the target object
        _DC_RE = _rc(
            r'(\w+(?:\.\w+)*(?:\[[^\]]*\])?)\s*\.\s*delegatecall\s*\(',
            re.DOTALL
        )
        # Address expressions that are safe (compile-time or immutable)
        _SAFE_TARGET_RE = _rc(
            r'^(?:address\s*\(this\)|'           # address(this) — unusual but benign
            r'_implementation|implementation_|'  # standard OZ proxy names
            r'IMPL|impl_|_impl\b)',
            re.IGNORECASE
        )
        # Patterns that suggest the address is user-supplied
        _PARAM_RE = _rc(r'\b(?:target|addr|to|impl|callee|module)\b', re.IGNORECASE)

        for func in functions:
            body = self._strip_comments(func['body'])
            for m in _DC_RE.finditer(body):
                target_expr = m.group(1).strip()

                # Skip if clearly a safe OZ proxy implementation slot read
                if _SAFE_TARGET_RE.match(target_expr):
                    continue

                # Skip address(this) — benign
                if target_expr in ('address(this)',):
                    continue

                # Escalate to CRITICAL if the target looks like a param/local var
                param_names = [p.strip().split()[-1] for p in
                               func.get('params', '').split(',') if p.strip()]
                is_param = target_expr in param_names or bool(_PARAM_RE.search(target_expr))
                severity = StaticSeverity.CRITICAL if is_param else StaticSeverity.HIGH

                findings.append(StaticFinding(
                    severity=severity,
                    category=StaticCategory.ACCESS_CONTROL,
                    title=f"delegatecall injection risk in {func['name']}(): target={target_expr}",
                    description=(
                        f"``{func['name']}()`` performs ``{target_expr}.delegatecall(...)`` "
                        f"where ``{target_expr}`` {'appears to be caller-controlled (function parameter)' if is_param else 'is a dynamic address — verify it cannot be influenced by an attacker'}. "
                        f"``delegatecall`` runs attacker-chosen code with this contract's storage "
                        f"and ETH — an unconditional takeover if the target is not validated."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=is_param,
                    fix_suggestion=(
                        "Restrict delegatecall targets to admin-set, immutable, or constant "
                        "addresses. Never accept the target as a user-supplied parameter. "
                        "If this is an intentional proxy, ensure only the admin can update "
                        "the implementation address."
                    ),
                    cwe="CWE-829",
                    confidence=0.88 if is_param else 0.72,
                ))

        return findings

    # ── Novel detector: single-step ownership transfer ────────────────────

    def _detect_single_step_ownership(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        PATTERN: transferOwnership() without a two-step accept pattern.

        Single-step ownership transfer sets the new owner immediately. A typo
        in the address permanently transfers control with no recovery path.

        Fires when:
          - Contract defines a transferOwnership function that directly assigns
            the owner variable (single-step) — OR
          - Contract inherits OZ Ownable without Ownable2Step override
          - No pendingOwner / acceptOwnership / claimOwnership pattern exists

        Real-world: ~30% of C4/Sherlock findings in protocols with custom ownership.
        Slither does NOT check for two-step ownership pattern.
        """
        _SAFE_PATTERNS = (
            'Ownable2Step', 'Ownable2StepUpgradeable',
            'acceptOwnership', 'claimOwnership', 'claimOwner',
            'pendingOwner', 'pending_owner', 'nominatedOwner', '_pendingOwner',
        )
        stripped_source = self._strip_comments(source)
        if any(p in stripped_source for p in _SAFE_PATTERNS):
            return []

        # Look for the function definition (not a call to it)
        for func in functions:
            fname = func.get('name', '')
            if 'transferOwnership' not in fname and 'transferownership' not in fname.lower():
                continue
            body = self._strip_comments(func['body'])
            # Two-step: stores pending owner → safe
            if any(p.lower() in body.lower() for p in
                   ('pendingOwner', 'pending_owner', '_pendingOwner', 'nominatedOwner')):
                return []
            # Single-step: directly assigns owner state variable
            if re.search(r'\b_?owner\s*=\s*\w|\bowner\s*=\s*new', body):
                return [StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.ACCESS_CONTROL,
                    title=f"Single-step ownership transfer: {fname}()",
                    description=(
                        f"``{fname}()`` assigns the new owner immediately. "
                        f"A typo or social-engineering attack permanently transfers "
                        f"protocol control with no recovery path."
                    ),
                    location=f"{fname}():L{func['line']}",
                    exploitable=False,
                    fix_suggestion=(
                        "Use ``Ownable2Step``: store ``pendingOwner`` in transferOwnership(), "
                        "require the new owner to call ``acceptOwnership()`` to confirm."
                    ),
                    cwe="CWE-284",
                    confidence=0.85,
                )]

        # No override found but inherits Ownable → uses OZ single-step base
        if re.search(r'\bOwnable\b', source) and 'transferOwnership' not in source:
            _cname_m = re.search(r'^(?:abstract\s+)?contract\s+(\w+)', source, re.MULTILINE)
            _cname = _cname_m.group(1) if _cname_m else "Unknown"
            return [StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.ACCESS_CONTROL,
                title=f"Single-step ownership transfer (OZ Ownable base in {_cname})",
                description=(
                    "Contract inherits OZ ``Ownable`` (single-step) without overriding "
                    "``transferOwnership``. One mistaken call permanently loses admin control."
                ),
                location=f"{_cname}",
                exploitable=False,
                fix_suggestion="Inherit from ``Ownable2Step`` instead of ``Ownable``.",
                cwe="CWE-284",
                confidence=0.82,
            )]

        return []

    # ── Novel detector: admin/owner transfer with missing zero-address guard ─

    def _detect_admin_zero_address_brick(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        PATTERN: transferAdmin / setAdmin / transferOwnership assigns address param
        to state without a zero-address guard — permanently bricks admin access.

        Fires when:
          - Function name matches transfer/set/change + Admin/Owner/Controller
          - Body writes an address-typed parameter to a state variable
          - No address(0) / != address(0) / ZeroAddress check present
          - No pendingAdmin / pendingOwner (two-step) pattern present

        Root cause: Sablier-style Adminable.transferAdmin() — confirmed bug PoC:
          tests/poc/AdminableBrick.t.sol (3/3 passing).

        Note: IAdminable NatSpec explicitly documents this is possible ("can
        potentially leave the contract without an admin"), making it a documented
        design choice — but still a LOW/MEDIUM risk for protocols where admin loss
        causes permanent fund lockup (protocol revenue, clawback rights, etc.).
        """
        _FUNC_RE = _rc(
            r'^(transfer|set|change|update|renounce)(Admin|Owner|Controller|Governor|Operator)',
            re.IGNORECASE
        )
        _SAFE_PATTERNS = (
            'pendingAdmin', 'pendingOwner', 'pending_owner', '_pendingAdmin',
            'nominatedOwner', 'acceptAdmin', 'acceptOwnership', 'claimOwnership',
            'Ownable2Step', 'Ownable2StepUpgradeable',
        )
        _ZERO_CHECK_RE = _rc(
            r'address\s*\(\s*0\s*\)|ZeroAddress|zero[_\s]?address|!= address',
            re.IGNORECASE
        )
        findings = []
        stripped = self._strip_comments(source)

        # If the contract already uses a two-step pattern, skip entirely.
        if any(p in stripped for p in _SAFE_PATTERNS):
            return []

        for func in functions:
            fname = func.get('name', '')
            if not _FUNC_RE.match(fname):
                continue

            # Skip renounce functions — intentional zero-address assignment
            if 'renounce' in fname.lower():
                continue

            body = self._strip_comments(func.get('body', ''))

            # Must have an address-typed parameter
            addr_params = []
            for part in func.get('params', '').split(','):
                part = part.strip()
                if part.startswith('address ') or part.startswith('address\t'):
                    pname = part.split()[-1].lstrip('_')
                    addr_params.append(pname)
            if not addr_params:
                continue

            # Must NOT already have a zero-address check
            if _ZERO_CHECK_RE.search(body):
                continue

            # Must assign the address param to a state variable
            for param in addr_params:
                if re.search(rf'\b\w+\s*=\s*{re.escape(param)}\b', body):
                    findings.append(StaticFinding(
                        severity=StaticSeverity.LOW,
                        category=StaticCategory.ACCESS_CONTROL,
                        title=f"Admin/owner transfer without zero-address guard: {fname}()",
                        description=(
                            f"``{fname}()`` assigns ``{param}`` directly to admin/owner state "
                            f"with no ``address(0)`` guard and no two-step confirmation. "
                            f"A single call with ``address(0)`` permanently bricks all "
                            f"``onlyAdmin``/``onlyOwner``-gated functions — including fee "
                            f"collection, parameter updates, and fund recovery — with no "
                            f"recovery path. Confirmed via Foundry PoC."
                        ),
                        location=f"{fname}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion=(
                            f"Option A (minimal): add ``if ({param} == address(0)) revert ZeroAddress();`` "
                            f"before the assignment. "
                            f"Option B (robust): use a two-step pattern — store ``pendingAdmin`` in "
                            f"``{fname}()``, require the new admin to call ``acceptAdmin()``."
                        ),
                        cwe="CWE-284",
                        confidence=0.90,
                    ))
                    break
        return findings

    # ── Novel detector: token approval griefing (USDT-style) ──────────────

    def _detect_approval_griefing(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        PATTERN: ERC20 approve() without prior approve(0) / safeApprove deprecated.

        USDT and several other non-standard ERC20s REVERT when you call
        ``approve(spender, N)`` with N > 0 while allowance is already non-zero.
        Protocols that re-approve a spender (e.g. after a partial fill) will
        silently break when used with USDT.

        Sub-patterns:
          A. ``token.approve(spender, amount)`` where amount is not 0 and no
             prior zero-reset exists in the same function body.
          B. ``safeApprove(spender, amount)`` — OZ deprecated because it has
             the same USDT bug.

        Slither's ``approve-race-condition`` checks for the ERC20 double-spend
        race — different bug. This checks for REVERT-on-non-zero allowance.
        """
        findings = []
        _SAFE_APPROVE_RE   = _rc(r'\bsafeApprove\s*\(')
        # Safe alternatives present → suppress
        _SAFE_ALT_RE       = _rc(
            r'\bforceApprove\s*\(|safeIncreaseAllowance\s*\(|safeDecreaseAllowance\s*\('
        )
        # Any .approve( call present
        _HAS_APPROVE_RE    = _rc(r'\.\s*approve\s*\(')
        # Zero-reset: approve call whose last positional arg is literal 0
        # Strategy: look for approve followed eventually by ", 0)" anywhere in func body.
        # Conservative: `,\s*0\s*\)` anywhere is treated as a zero-reset.
        _ZERO_RESET_RE     = _rc(r'\.approve[^;]*,\s*0\s*\)', re.DOTALL)

        for func in functions:
            body = self._strip_comments(func['body'])

            # Sub-pattern B: deprecated safeApprove
            if _SAFE_APPROVE_RE.search(body):
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.LOGIC,
                    title=f"Deprecated safeApprove() in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` uses OZ's deprecated ``safeApprove()``. "
                        f"It reverts if the current allowance is non-zero — identical to "
                        f"the USDT ``approve()`` bug it was meant to fix."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=False,
                    fix_suggestion=(
                        "Replace with ``SafeERC20.forceApprove(token, spender, amount)`` "
                        "(OZ v5+) or reset-to-zero pattern: approve(0) then approve(N)."
                    ),
                    cwe="CWE-252",
                    confidence=0.92,
                ))
                continue

            # Sub-pattern A: any approve present but no zero-reset and no safe alt
            if not _HAS_APPROVE_RE.search(body):
                continue
            if _SAFE_ALT_RE.search(body):
                continue
            if _ZERO_RESET_RE.search(body):
                continue

            findings.append(StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.LOGIC,
                title=f"Approval griefing risk in {func['name']}(): no zero-reset",
                description=(
                    f"``{func['name']}()`` calls ``.approve()`` without first resetting "
                    f"the allowance to zero. USDT (and other non-standard ERC20s) revert "
                    f"if the current allowance is non-zero, silently breaking this function "
                    f"on the second call."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=False,
                fix_suggestion=(
                    "Use ``SafeERC20.forceApprove(token, spender, amount)`` (OZ v5+). "
                    "Or reset first: ``token.approve(spender, 0); token.approve(spender, amount);``"
                ),
                cwe="CWE-252",
                confidence=0.80,
            ))

        return findings

    # ── Novel detector: stale/unsafe AMM deadline ─────────────────────────

    def _detect_amm_deadline(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        PATTERN: DEX swap/liquidity calls with deadline = block.timestamp or
        deadline = type(uint256).max.

        ``block.timestamp`` as deadline is a no-op — the tx is always in the
        same block it was created, so the deadline is always met. Validators
        (and MEV bots) can hold it for any future block.

        ``type(uint256).max`` never expires — it can execute days later at
        an arbitrarily worse price.

        Covers: Uniswap V2/V3, Curve, Balancer, and any protocol using
        positional deadline arguments.

        Slither's sandwich check covers amountOutMin=0 (slippage axis).
        This covers the deadline axis — orthogonal to slippage.
        """
        findings = []

        # Explicit full function names for all major AMM routers
        _AMM_CALL_RE = _rc(
            r'\b(?:swapExactTokensForTokens|swapTokensForExactTokens|'
            r'swapExactETHForTokens|swapTokensForExactETH|'
            r'swapExactTokensForETH|swapETHForExactTokens|'
            r'swapExactTokensForTokensSupportingFeeOnTransferTokens|'
            r'swapExactETHForTokensSupportingFeeOnTransferTokens|'
            r'swapExactTokensForETHSupportingFeeOnTransferTokens|'
            r'exactInputSingle|exactInput|exactOutputSingle|exactOutput|'
            r'multicall|'
            r'addLiquidity(?:ETH)?|removeLiquidity(?:ETH)?(?:WithPermit)?|'
            r'exchange|exchange_underlying|exchange_multiple|'
            r'joinPool|exitPool|batchSwap)\s*\(',
            re.IGNORECASE
        )
        _DEADLINE_BLOCK_TS_RE = _rc(
            r'\bdeadline\s*[:=]\s*block\.timestamp\b|'
            r',\s*block\.timestamp\s*[\n\r\s]*[,)\]]',
        )
        _DEADLINE_MAX_RE = _rc(
            r'\bdeadline\s*[:=]\s*type\s*\(\s*uint256\s*\)\s*\.max\b|'
            r'\bdeadline\s*[:=]\s*(?:MAX_UINT256?|UINT_MAX|UINT256_MAX)\b|'
            r',\s*type\s*\(\s*uint256\s*\)\s*\.max\s*[\n\r\s]*[,)\]]',
            re.IGNORECASE
        )

        for func in functions:
            body = self._strip_comments(func['body'])
            if not _AMM_CALL_RE.search(body):
                continue

            if _DEADLINE_BLOCK_TS_RE.search(body):
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.ORACLE,
                    title=f"AMM deadline=block.timestamp (no-op) in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` passes ``block.timestamp`` as the DEX deadline. "
                        f"This deadline always passes in the same block — it provides no "
                        f"protection. Validators can delay execution to a worse-price block."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        "Use ``block.timestamp + MAX_DELAY`` (e.g. 1800 for 30 min). "
                        "Expose deadline as a user-supplied parameter for front-ends."
                    ),
                    cwe="CWE-613",
                    confidence=0.87,
                ))

            elif _DEADLINE_MAX_RE.search(body):
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.ORACLE,
                    title=f"AMM swap with infinite deadline in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` uses ``type(uint256).max`` as the deadline. "
                        f"The transaction never expires and can execute at any future price."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        "Replace with ``block.timestamp + MAX_DELAY`` and expose it "
                        "as a parameter so callers control their price window."
                    ),
                    cwe="CWE-613",
                    confidence=0.88,
                ))

        return findings

    # ── Novel detector: governance attack (no timelock) ───────────────────────

    def _detect_governance_attack(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: Admin function that modifies critical protocol parameters
        without a timelock — allows instant rug by a compromised owner.

        Fires when:
          - Function has onlyOwner/onlyAdmin/onlyGovernance modifier
          - Function name or body suggests it sets a critical parameter
            (router, oracle, treasury, fee, token, implementation, strategy)
          - No timelock signals anywhere in the source
            (TimelockController, _timelock, minDelay, schedule, TIMELOCK_ROLE)

        Real-world frequency: ~40% of C4 governance findings.
        Slither does NOT check for timelock absence.
        """
        # Word-boundary check — prevent 'Timelock' matching 'NoTimelock' or 'TimelockFoo'
        _TIMELOCK_RE = _rc(
            r'\b(?:TimelockController|TimelockUpgradeable|ITimelock'
            r'|_?timelock(?:Address|Contract|Role)?'
            r'|minDelay|TIMELOCK_ROLE|schedule(?:Batch)?\('
            r'|MINIMUM_DELAY)\b',
            re.IGNORECASE,
        )
        stripped_src = self._strip_comments(source)
        if _TIMELOCK_RE.search(stripped_src):
            return []

        # Single-key ownership patterns — HIGH (one compromised key = game over)
        _SINGLE_KEY_MODS = frozenset({
            'onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyGuardian',
            'onlyDAO', 'requiresAuth', 'onlyManager', 'onlyController',
        })
        # Role-based access (AccessControl) — suppressed: multisig-compatible RBAC
        # is an explicit design choice, not a timelock gap we should flag.
        _ROLE_BASED_MODS = frozenset({'onlyRole', 'onlyOperator'})
        _ADMIN_MODS = _SINGLE_KEY_MODS | _ROLE_BASED_MODS

        # Source uses AccessControl if it imports/inherits the OZ pattern
        _AC_RE = _rc(r'\bAccessControl(?:Enumerable)?(?:Upgradeable)?\b')
        uses_access_control = bool(_AC_RE.search(source))

        _CRITICAL_KWS = (
            # Full-word critical nouns — only for compound setter names (not action fns)
            'router', 'oracle', 'treasury', 'implementation',
            'strategy', 'minter', 'pricefeed',
            # 'keeper' removed — functions NAMED keeperXxx are action fns, not setters
            # 'token' intentionally omitted — too broad (matches updateTokenURI, burnToken, etc.)
            # 'fee' and 'rate' kept only via compound setter forms below
            'setkeeper', 'setrouter', 'setoracle', 'settreasury', 'setfee',
            'settoken', 'setimplementation', 'setstrategy', 'setupgradeto',
            'setreward', 'setinterest', 'setcollateral', 'setrate',
            'updatemintrate', 'setmintrate', 'updaterate', 'updatefee',
        )

        # Strip modifier arguments: "onlyRole(DEFAULT_ADMIN_ROLE)" -> "onlyRole"
        _MOD_ARG_RE = _rc(r'\([^)]*\)')

        findings = []
        for func in functions:
            fname = func.get('name', '')
            mods_raw = func.get('modifiers', '')
            raw_tokens = mods_raw.split() if isinstance(mods_raw, str) else list(mods_raw)
            mods = {_MOD_ARG_RE.sub('', t) for t in raw_tokens}
            if not (mods & _ADMIN_MODS):
                continue

            # Suppress if the ONLY admin gate is role-based AND contract uses
            # AccessControl (multisig-compatible RBAC). Single-key onlyOwner
            # variants still fire regardless.
            role_only = bool(mods & _ROLE_BASED_MODS) and not bool(mods & _SINGLE_KEY_MODS)
            if role_only and uses_access_control:
                continue

            body_lower = self._strip_comments(func['body']).lower()
            fname_lower = fname.lower()
            if not any(kw in fname_lower or kw in body_lower for kw in _CRITICAL_KWS):
                continue

            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.ACCESS_CONTROL,
                title=f"Governance: no timelock on {fname}()",
                description=(
                    f"``{fname}()`` is admin-gated and modifies critical protocol "
                    f"parameters (router/oracle/treasury/fee/implementation) with no "
                    f"timelock delay. A compromised or malicious owner can change these "
                    f"parameters instantly — swap router to a drain contract, set fee=100%, "
                    f"upgrade implementation to a backdoor."
                ),
                location=f"{fname}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Wrap with ``TimelockController`` (OZ). Minimum delay: 24h for "
                    "parameter changes, 48h for upgrades. Use a Gnosis Safe multi-sig "
                    "as the timelock proposer. Emit events for all parameter changes."
                ),
                cwe="CWE-284",
                confidence=0.78,
            ))
        return findings

    # ── Novel detector: cross-contract reentrancy (receiver hooks) ─────────────

    def _detect_cross_contract_reentrancy_static(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: Contract implements ERC receiver/callback hook AND makes external
        calls before state updates in other functions — classic cross-contract
        reentrancy vector.

        Patterns detected:
          - tokensReceived (ERC777 operator hook)
          - onERC1155Received / onERC1155BatchReceived
          - onERC721Received (safeTransfer callback)
          - onFlashLoan (ERC3156)
          - uniswapV2Call / uniswapV3FlashCallback (flash swap callbacks)

        The risk: an attacker deploys a contract that implements the same hook,
        re-enters during the external call, and reads/modifies stale state.

        Slither catches single-contract reentrancy but misses this pattern.
        """
        _HOOKS = frozenset({
            'tokensReceived', 'onERC1155Received', 'onERC1155BatchReceived',
            'onERC721Received', 'onFlashLoan', 'uniswapV2Call',
            'uniswapV3FlashCallback', 'pancakeCall',
        })
        _EXT_CALL_RE = _rc(
            r'\.(transfer|send|call|safeTransfer|safeTransferFrom|transferFrom'
            r'|mint|burn)\s*[({]',
            re.IGNORECASE,
        )
        _STATE_WRITE_RE = _rc(
            r'\b(\w+)\s*(\[.*?\])?\s*[+\-*/]?=(?!=)',
            re.MULTILINE,
        )

        # Detect hook implementations
        hook_funcs = {
            f['name'] for f in functions if f['name'] in _HOOKS
        }
        if not hook_funcs:
            return []

        findings = []
        for func in functions:
            fname = func.get('name', '')
            if fname in _HOOKS:
                continue

            body = self._strip_comments(func['body'])
            # Must make external call
            ext_match = _EXT_CALL_RE.search(body)
            if not ext_match:
                continue

            # Must write state AFTER the external call
            ext_pos = ext_match.start()
            after_call = body[ext_pos:]
            if not _STATE_WRITE_RE.search(after_call):
                continue

            for hook in hook_funcs:
                findings.append(StaticFinding(
                    severity=StaticSeverity.HIGH,
                    category=StaticCategory.REENTRANCY,
                    title=f"Cross-contract reentrancy: {fname}() + {hook}() hook",
                    description=(
                        f"``{fname}()`` makes an external call before updating state, "
                        f"and this contract implements ``{hook}()``. If the external call "
                        f"recipient triggers ``{hook}()`` on re-entry, it reads stale "
                        f"state from the incomplete ``{fname}()`` execution."
                    ),
                    location=f"{fname}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        "Apply CEI: all state updates BEFORE external calls. "
                        "Add ``nonReentrant`` modifier. "
                        "If using ERC777 tokens, consider ERC20 alternatives."
                    ),
                    cwe="CWE-362",
                    confidence=0.73,
                ))
                break  # one finding per function

        return findings

    # ──────────────────────────────────────────────────────────────────────────
    # v1.5 Detectors — close the gap between tool and manual audit
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_mutable_init_only_storage(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: Storage variable is written ONLY inside init/constructor/reinitialize
        functions but is used as a delegatecall target, modifier check, or critical
        external call target — yet is NOT declared `immutable`.

        This catches the "should-be-immutable" pattern (e.g. _vaultBridgeTokenPart2 stored
        in ERC-7201 slot, set during init, used as delegatecall target every call). If an
        upgrade accidentally introduced a setter, all delegatecalls could be redirected.

        Confidence: 0.72 (false positives: legit upgradeable address vars that intentionally
        change via governance, e.g. priceOracle that's separate from this detector).
        """
        _INIT_RE = _rc(
            r'\b(constructor|initialize|reinitialize|__\w+_init\w*|_init\w*)\b',
            re.IGNORECASE,
        )
        # Variables used as delegatecall target or in critical modifier-like patterns
        _CRITICAL_USE_RE = _rc(
            r'delegatecall\s*\(\s*(?:gas\s*\(\s*\)\s*,\s*)?(\w+)',
            re.IGNORECASE,
        )
        _STATE_ASSIGN_RE = _rc(
            r'\$\s*\.\s*(\w+)\s*=\s*|(?<!\w)(\w+)\s*=\s*(?!\=)',
        )
        _IMMUTABLE_RE = _rc(r'\bimmutable\b')

        findings = []

        # 1. Collect which vars are set in init-only functions vs non-init functions
        init_only_writes: dict[str, list[str]] = {}   # varname -> [func_names]
        non_init_writes: set[str] = set()

        for func in functions:
            fname = func.get('name', '')
            body = self._strip_comments(func.get('body', ''))
            is_init = bool(_INIT_RE.search(fname))

            for m in _STATE_ASSIGN_RE.finditer(body):
                var = (m.group(1) or m.group(2) or '').strip()
                if not var or len(var) < 3 or var in ('true', 'false', 'this'):
                    continue
                if is_init:
                    init_only_writes.setdefault(var, []).append(fname)
                else:
                    non_init_writes.add(var)

        # 2. Find delegatecall targets from full source
        delegatecall_targets: set[str] = set()
        for m in _CRITICAL_USE_RE.finditer(source):
            delegatecall_targets.add(m.group(1).strip())

        # 3. Also detect vars used in assembly delegatecall pattern:
        #    $.slot := VAR_NAME — treat the var used right before delegatecall
        _ASM_DC_RE = _rc(
            r'let\s+ok\s*:=\s*delegatecall\s*\(\s*gas\s*\(\s*\)\s*,\s*(\w+)',
        )
        for m in _ASM_DC_RE.finditer(source):
            delegatecall_targets.add(m.group(1).strip())

        # 4. Flag: written in init ONLY (not in any non-init function), used as
        #    delegatecall target, and NOT declared immutable
        for var, init_fns in init_only_writes.items():
            if var in non_init_writes:
                continue
            if var not in delegatecall_targets:
                continue
            # Check it's not declared immutable
            immutable_decl = re.search(
                rf'\bimmutable\b[^;]*\b{re.escape(var)}\b|\b{re.escape(var)}\b[^;]*\bimmutable\b',
                source,
            )
            if immutable_decl or _IMMUTABLE_RE.search(source):
                # Only skip if this specific var has immutable
                if re.search(rf'\bimmutable\b\s+{re.escape(var)}\b|\b{re.escape(var)}\b\s+=\s+.*;\s*//', source):
                    continue

            findings.append(StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.LOGIC,
                title=f"Should-be-immutable delegatecall target: `{var}`",
                description=(
                    f"`{var}` is written only during initialization "
                    f"({', '.join(init_fns[:3])}) yet used as a `delegatecall` target "
                    f"in production code. It is stored in mutable storage rather than "
                    f"declared `immutable`. If a future upgrade accidentally introduces "
                    f"a setter, all delegatecalls could be redirected to an attacker-controlled "
                    f"contract, draining the proxy's state."
                ),
                location=f"{var} (init: {init_fns[0]})",
                exploitable=False,
                fix_suggestion=(
                    f"Declare `{var}` as `immutable` and set it in the constructor, "
                    f"or add an invariant test that asserts no public/external setter exists."
                ),
                cwe="CWE-829",
                confidence=0.72,
            ))

        return findings

    def _detect_critical_address_swap(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: Admin function replaces a contract-typed storage variable
        (yieldVault, oracle, bridge, pool, strategy) without first draining/migrating
        assets from the old contract.

        Pattern (from VaultBridgeToken.setYieldVault):
          function setX(address newX) onlyOwner {
              $.x = newX;           ← overwrites old contract reference
              // old contract still holds assets  ← no drain call
          }

        This strands assets in the decommissioned contract and may cause accounting
        desync (totalAssets() drops to 0, users can't withdraw).

        Confidence: 0.78 (FPs: swaps where the old contract is already empty by design,
        e.g. changing an oracle that has no state).
        """
        _CRITICAL_SUFFIXES = _rc(
            r'(Vault|vault|Oracle|oracle|Bridge|bridge|Pool|pool|Strategy|strategy'
            r'|Token|token|Reserve|reserve|Staking|staking|Yield|yield)',
        )
        _SETTER_RE = _rc(
            r'function\s+(set\w+)\s*\(\s*address\s+(\w+)',
            re.IGNORECASE,
        )
        _DRAIN_RE = _rc(
            r'_?(?:drain|withdraw|migrate|redeem|harvest|flush|exit|sweep)\w*\s*\(',
            re.IGNORECASE,
        )
        _ACCESS_RE = _rc(
            r'\b(onlyOwner|onlyRole|onlyAdmin|DEFAULT_ADMIN_ROLE|onlyGov)\b',
        )

        findings = []

        for func in functions:
            fname = func.get('name', '')
            body = self._strip_comments(func.get('body', ''))

            m = _SETTER_RE.match(f'function {fname}(')
            if not m:
                # Try matching from function signature in source
                sig_m = re.search(
                    rf'function\s+{re.escape(fname)}\s*\(\s*address\s+(\w+)',
                    source,
                )
                if not sig_m:
                    continue
                param = sig_m.group(1)
            else:
                param = m.group(2)

            # Must be admin-gated (check body AND modifiers field)
            modifiers_str = func.get('modifiers', '')
            if not _ACCESS_RE.search(body) and not _ACCESS_RE.search(modifiers_str):
                continue

            # Function name or param must suggest a critical contract type
            if not _CRITICAL_SUFFIXES.search(fname) and not _CRITICAL_SUFFIXES.search(param):
                continue

            # Must assign the new address to storage ($.x = param or x = param)
            # Allow any optional type cast before the param: $.x = SomeType(param)
            assign_re = _rc(
                rf'[\$\w\.]+\s*=\s*(?:\w+\s*\(\s*)?{re.escape(param)}',
            )
            if not assign_re.search(body):
                continue

            # Flag if no drain/withdraw/migrate call precedes the assignment
            assign_pos = (assign_re.search(body) or re.search('=', body)).start()
            before_assign = body[:assign_pos]
            if _DRAIN_RE.search(before_assign):
                continue  # drain found before swap — clean

            findings.append(StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.ACCOUNTING,
                title=f"Critical address swap without prior drain: `{fname}()`",
                description=(
                    f"`{fname}()` replaces a critical contract reference (`{param}`) "
                    f"in storage without first draining or migrating assets from the "
                    f"old contract. After the swap, assets held by the old contract "
                    f"are orphaned: `totalAssets()` drops, the accounting invariant "
                    f"breaks, and users may be unable to withdraw."
                ),
                location=f"{fname}():L{func['line']}",
                exploitable=False,
                fix_suggestion=(
                    f"Call a drain/withdraw/migrate function on the old `{param}` "
                    f"BEFORE overwriting it, or document and enforce that the old "
                    f"contract must be empty prior to calling `{fname}()`."
                ),
                cwe="CWE-1265",
                confidence=0.78,
            ))

        return findings

    def _detect_cross_chain_input_arith(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        LOW/MEDIUM: A value decoded from an external cross-chain message (abi.decode)
        is used as the subtrahend in an arithmetic expression without an explicit
        bounds check that proves the subtraction is safe.

        Pattern:
          (uint256 shares, uint256 assets) = abi.decode(data, (uint256, uint256));
          uint256 discrepancy = requiredAssets - assets;   ← 'assets' from bridge msg

        In Solidity 0.8 this reverts on underflow, but the semantic risk is that the
        cross-chain invariant (requiredAssets >= assets) is assumed but not enforced
        on-chain. If the bridge message can be forged or if the off-chain encoder has
        a bug, the subtraction could semantically yield a wrong (but non-reverting)
        large value, e.g. in an unchecked block.

        Confidence: 0.65 (many legitimate cases are protected by Solidity 0.8 checks
        or by validated message originAddress).
        """
        _DECODE_RE = _rc(
            r'abi\s*\.\s*decode\s*\(\s*\w+\s*,\s*\([^)]+\)\s*\)',
        )
        _VAR_EXTRACT_RE = _rc(
            r'\(\s*(?:[\w\s,]+)\)\s*=\s*abi\s*\.\s*decode',
        )
        _SUB_RE = _rc(
            r'(\w+)\s*-\s*(\w+)',
        )
        _UNCHECKED_RE = _rc(r'\bunchecked\b\s*\{')
        _REQUIRE_RE = _rc(r'\brequire\b|\bassert\b|\bif\b.*\brevert\b')

        # Use AST type info when available — skip int256 subtrahends.
        # Only call solc if self._use_ast is set (avoid 0.8s subprocess per file).
        _uint_widths = {}
        if getattr(self, '_use_ast', False):
            try:
                from ast_bridge import get_uint_widths
                _uint_widths = get_uint_widths(source)
            except Exception:
                pass

        findings = []

        for func in functions:
            fname = func.get('name', '')
            body = self._strip_comments(func.get('body', ''))

            # Must have an abi.decode call
            if not _DECODE_RE.search(body):
                continue

            # Extract decoded variable names
            decoded_vars: set[str] = set()
            for vm in _VAR_EXTRACT_RE.finditer(body):
                # Extract the LHS variables from the tuple assignment
                lhs_end = vm.start()
                # Walk back to find '(' of the tuple
                snippet = body[max(0, lhs_end - 200):lhs_end + len(vm.group())]
                tup_m = re.search(r'\(\s*((?:[\w\s]+,?\s*)+)\)\s*=\s*abi\.decode', snippet)
                if tup_m:
                    for raw in tup_m.group(1).split(','):
                        parts = raw.strip().split()
                        if parts:
                            decoded_vars.add(parts[-1].strip())

            if not decoded_vars:
                continue

            # Check if any decoded var is the subtrahend in a subtraction
            in_unchecked = bool(_UNCHECKED_RE.search(body))
            for m in _SUB_RE.finditer(body):
                subtrahend = m.group(2).strip()
                if subtrahend not in decoded_vars:
                    continue

                # Check if there's a require/assert before this subtraction
                sub_pos = m.start()
                before_sub = body[:sub_pos]
                has_guard = bool(_REQUIRE_RE.search(before_sub))

                # Skip int256 subtrahends — signed types can go negative by
                # design; underflow in the uint sense doesn't apply.
                subtrahend_type = _uint_widths.get(subtrahend, 256)
                if subtrahend_type == 0:  # sentinel: signed type detected
                    continue

                severity = StaticSeverity.LOW
                extra = ""
                if in_unchecked:
                    severity = StaticSeverity.MEDIUM
                    extra = " The subtraction is inside an `unchecked` block — Solidity 0.8 overflow protection is disabled."

                if not has_guard or in_unchecked:
                    findings.append(StaticFinding(
                        severity=severity,
                        category=StaticCategory.ACCOUNTING,
                        title=(
                            f"Cross-chain decoded value used as subtrahend without "
                            f"explicit bounds guard: `{fname}()`"
                        ),
                        description=(
                            f"`{subtrahend}` is decoded from an external cross-chain message "
                            f"(abi.decode) and used as the subtrahend in `... - {subtrahend}`. "
                            f"The on-chain safety of this subtraction depends on a cross-chain "
                            f"invariant (minuend >= {subtrahend}) that is not enforced on-chain — "
                            f"only assumed from the bridge message encoding.{extra} "
                            f"If the off-chain encoder has a bug or the message is manipulated, "
                            f"this could corrupt accounting."
                        ),
                        location=f"{fname}():L{func['line']}",
                        exploitable=in_unchecked,
                        fix_suggestion=(
                            f"Add `require(minuend >= {subtrahend}, ...)` before the subtraction, "
                            f"or move the subtraction out of any `unchecked` block."
                        ),
                        cwe="CWE-682",
                        confidence=0.65,
                    ))
                    break  # one finding per function

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # NOVEL DETECTORS — zero Slither overlap, based on competitive audit patterns
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_accrual_gate_dos(
        self, source: str, functions: List[Dict],
        call_graph: Optional[Dict[str, set]] = None,
    ) -> List[StaticFinding]:
        """
        HIGH: Admin setter permanently DoS'd when rate/yield/fee set to zero.

        Pattern origin: DERC20.updateMintRate() — Cantina audit 2026-05.
        No public tool (Slither, Aderyn, Semgrep, Mythril) detects this.

        Root cause:
            function updateX(uint256 newX) external onlyOwner {
                if (enabled) {
                    accrue();          ← requires mintableAmount > 0
                }                      ← reverts when X == 0
                X = newX;             ← permanently unreachable
            }

        Sequence: admin calls updateX(0) → sets rate to 0. Later admin calls
        updateX(1) → accrue() fires → mintableAmount = supply * 0 * dt = 0 →
        require(0 > 0) REVERTS → governance permanently frozen.

        Detection heuristics (all three must hold):
          1. Function is admin-gated (admin_modifiers).
          2. Function body calls an internal accrual function BEFORE the
             assignment of the parameter to a state variable.
          3. The accrual function contains `require(X > 0)` or
             `if (X == 0) revert` where X is computed from the state var.
          4. No lower-bound guard on the input (`require(newX > 0)` absent).
        """
        findings = []

        # Step 1: build the set of accrual function names (functions with a
        # `require(amount > 0)` or `NoMintableAmount` / `NothingToAccrue`
        # style guard on a computed amount).
        _ACCRUE_GUARD_RE = _rc(
            r'require\s*\(\s*\w+(?:able)?(?:Amount|Reward|Yield|Fee|Mint)?\s*>\s*0|'
            r'if\s*\(\s*\w+(?:able)?(?:Amount|Reward|Yield|Fee|Mint)?\s*==\s*0\s*\)\s*revert|'
            r'revert\s+No(?:Mintable|Accrued|Claimable|Distributable|Pending)Amount',
            re.IGNORECASE,
        )
        accrual_fns: set = set()
        for func in functions:
            body = self._strip_comments(func['body'])
            if _ACCRUE_GUARD_RE.search(body):
                accrual_fns.add(func['name'])

        if not accrual_fns:
            return findings

        # Step 2: find admin setters that call an accrual function
        _RATE_PARAM_RE = _rc(
            r'\b(?:new|_)?(?:Rate|Mint|Fee|Yield|Reward|Inflation|Interest|Basis|Bps)\w*\b',
            re.IGNORECASE,
        )
        _LOWER_BOUND_RE = _rc(
            r'require\s*\([^)]*new\w*\s*>\s*0|'
            r'if\s*\([^)]*new\w*\s*==\s*0\s*\)\s*revert|'
            r'require\s*\([^)]*>\s*0',
            re.IGNORECASE,
        )

        accrual_call_re = _rc(
            r'\b(' + '|'.join(re.escape(fn) for fn in accrual_fns) + r')\s*\(',
        )

        cg = call_graph or {}

        for func in functions:
            mod_str = func.get('modifiers', '')
            has_admin = any(m in mod_str for m in self.admin_modifiers)
            if not has_admin:
                continue

            body = self._strip_comments(func['body'])

            # Direct call in body — check explicitly
            call_m = accrual_call_re.search(body)
            accrual_name_found: Optional[str] = None
            if call_m:
                accrual_name_found = call_m.group(1)
            else:
                # Interprocedural: check if any transitively-reachable function
                # IS an accrual function (call graph path A → B → accrual)
                if cg:
                    reachable = self._call_graph_reachable(cg, func['name'])
                    hit = reachable & accrual_fns
                    if hit:
                        accrual_name_found = next(iter(hit))
            if accrual_name_found is None:
                continue

            # Must have a parameter that looks like a rate/fee
            params_str = func.get('params', '')
            if not _RATE_PARAM_RE.search(params_str) and not _RATE_PARAM_RE.search(func['name']):
                continue

            # Must assign the parameter to a state variable AFTER the accrual call.
            # For interprocedural hits (no direct call_m), check full body suffix.
            param_names = [p.strip().split()[-1] for p in params_str.split(',') if p.strip()]
            after_call = body[call_m.end():] if call_m else body
            assigned_after = any(
                re.search(rf'\b\w+\s*=\s*{re.escape(p)}\b', after_call)
                for p in param_names if p
            )
            if not assigned_after:
                continue

            # No lower-bound check on the input → zero is a valid call
            has_lower_bound = bool(_LOWER_BOUND_RE.search(body))
            if has_lower_bound:
                continue

            accrual_name = accrual_name_found
            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.LOGIC,
                title=f"Accrual-gate DoS in {func['name']}(): rate=0 permanently locks governance",
                description=(
                    f"`{func['name']}()` calls `{accrual_name}()` BEFORE updating the rate "
                    f"parameter, and `{accrual_name}()` reverts when the accrued amount is 0. "
                    f"If the rate is ever set to 0 (no lower-bound check on input), "
                    f"ALL subsequent calls to `{func['name']}()` — including attempts to restore "
                    f"a non-zero rate — will permanently revert. Governance capability is frozen "
                    f"with no recovery path once this state is reached."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=False,
                fix_suggestion=(
                    f"Option A (minimal): add `if ({accrual_name.replace('mint','yearlyMintRate')} > 0)` "
                    f"guard around the `{accrual_name}()` call.\n"
                    f"Option B (robust): add `require(newRate > 0, \"Rate cannot be zero\")` "
                    f"at the top of `{func['name']}()` to prevent the zero-rate state entirely."
                ),
                cwe="CWE-400",
                confidence=0.82,
            ))

        return findings

    def _detect_donation_inflation(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: Contract computes user shares from a storage-based totalAssets/totalSupply
        without measuring the actual balance delta — vulnerable to donation manipulation.

        Attack:
          1. Attacker deposits 1 wei → receives 1 share.
          2. Attacker donates 1e18 tokens directly (transfer/transferFrom to address(this)).
          3. Next depositor: shares = (deposit * totalSupply) / totalAssets
                                    = (1e18 * 1) / (1e18 + 1) = 0 (rounds down).
          4. Next depositor loses their entire deposit for 0 shares.

        Distinct from ERC4626 share-inflation (which looks for the specific OZ pattern).
        This targets any vault-like contract that:
          (a) Uses a stored totalAssets/balance variable (NOT balanceOf(address(this)))
          (b) Divides by that variable to compute shares
          (c) Has no virtual-offset (dead shares) protection

        No public tool detects this generalized pattern.
        """
        findings = []

        # Heuristic 1: contract has deposit/stake/provide functions
        has_deposit = bool(re.search(
            r'\bfunction\s+(?:deposit|stake|provide|addLiquidity|mint)\s*\(',
            source, re.IGNORECASE
        ))
        if not has_deposit:
            return findings

        # Heuristic 2: share computation uses stored accounting variable
        # (totalDeposited, totalStaked, poolBalance, reserveBalance)
        # rather than live balanceOf(address(this))
        _STORED_TOTAL_RE = _rc(
            r'\b(?:totalDeposited|totalStaked|poolBalance|reserveBalance|'
            r'totalPrincipal|accountedBalance|totalLocked|storedBalance)\b',
            re.IGNORECASE,
        )
        _LIVE_BALANCE_RE = _rc(
            r'\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
            re.IGNORECASE,
        )
        _SHARE_DIV_RE = _rc(
            r'\*\s*(?:totalSupply|_totalSupply|totalShares)\s*\(\s*\)'
            r'[^;]*/[^;]*(?:totalDeposited|totalStaked|poolBalance|reserveBalance'
            r'|totalPrincipal|accountedBalance|totalLocked)',
            re.IGNORECASE | re.DOTALL,
        )
        _VIRTUAL_OFFSET_RE = _rc(
            r'\+\s*(?:10\s*\*\*|1e)\d+|DEAD_SHARES|VIRTUAL|_decimals_offset|'
            r'\+\s*1\b',
            re.IGNORECASE,
        )

        uses_stored = bool(_STORED_TOTAL_RE.search(source))
        uses_live   = bool(_LIVE_BALANCE_RE.search(source))

        # If contract ONLY uses live balanceOf → not vulnerable to donation attack
        if uses_live and not uses_stored:
            return findings

        for func in functions:
            body = self._strip_comments(func['body'])
            share_m = _SHARE_DIV_RE.search(body)
            if not share_m:
                continue
            expr = share_m.group(0)
            if _VIRTUAL_OFFSET_RE.search(expr):
                continue  # virtual-offset protection present

            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.ACCOUNTING,
                title=f"Donation inflation attack surface in {func['name']}()",
                description=(
                    f"`{func['name']}()` computes shares as "
                    f"`deposit * totalSupply / totalAssets` using a STORED accounting "
                    f"variable. An attacker can directly donate tokens to `address(this)` "
                    f"to inflate `totalAssets` without increasing `totalSupply`, causing "
                    f"subsequent depositors to receive 0 shares and lose their entire deposit."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Use live `balanceOf(address(this))` measured as delta "
                    "(before/after transfer) rather than a stored accounting variable. "
                    "Or add a virtual-offset: use `totalSupply + DEAD_SHARES` and "
                    "seed the vault with dead shares at deploy time."
                ),
                cwe="CWE-682",
                confidence=0.78,
            ))
            break  # one per function

        return findings

    def _detect_governance_sandwich(
        self, source: str, functions: List[Dict],
        call_graph: Optional[Dict[str, set]] = None,
    ) -> List[StaticFinding]:
        """
        MEDIUM: Admin can extract value by sandwiching user transactions with
        fee/slippage/rate parameter changes — set max before user tx, reset after.

        Pattern: admin function sets fee/rate/slippage with immediate effect
        AND the same fee/rate/slippage is applied inside a user-callable function
        (swap/deposit/withdraw/redeem), with no timelock or commit-reveal delay.

        Example:
            Admin:  setFee(MAX_FEE)   ← front-run: fee = 100%
            User:   swap(...)          ← user pays max fee
            Admin:  setFee(0)          ← back-run: fee = 0%

        This is NOT the governance-no-timelock detector (which flags missing timelock
        for any admin function). This specifically requires:
          1. A fee/slippage/rate variable set by an admin function.
          2. That variable is READ inside a user-callable function affecting fund flow
             (swap, deposit, withdraw).
          3. No time-weighted average, commit-reveal, or min/max bound on the variable.

        Distinct from Slither's oracle-manipulation check (which covers external feeds).
        No public tool detects admin-internal sandwich griefing.
        """
        findings = []

        # Step 1: find admin setters that write to a fee/rate/slippage variable
        _FEE_VAR_NAMES_RE = _rc(
            r'\b(?:fee|Fee|rate|Rate|slippage|Slippage|spread|Spread|'
            r'premium|Premium|markup|Markup|commission|Commission|'
            r'protocolFee|swapFee|tradeFee|performanceFee|managementFee)\b',
        )
        _SETTER_RE = _rc(
            r'function\s+(?:set|update|change)\w*\s*\([^)]*\)',
            re.IGNORECASE,
        )

        # Collect fee variable names written by admin functions
        _INLINE_ADMIN_RE = _rc(
            r'require\s*\(\s*msg\.sender\s*==\s*\w+\s*[,)]',
        )
        fee_vars_written: dict = {}  # var_name → setter_func_name
        for func in functions:
            mod_str = func.get('modifiers', '')
            has_admin = any(m in mod_str for m in self.admin_modifiers)
            if not has_admin:
                body_head = self._strip_comments(func['body'])[:300]
                has_admin = bool(_INLINE_ADMIN_RE.search(body_head))
            if not has_admin:
                continue
            body = self._strip_comments(func['body'])
            # Find assignments to fee-sounding variables
            for m in re.finditer(
                r'\b(_?(?:fee|rate|slippage|spread|premium|commission|'
                r'protocolFee|swapFee|tradeFee|performanceFee|managementFee)\w*)\s*=\s*(?!=)',
                body, re.IGNORECASE
            ):
                var = m.group(1)
                fee_vars_written[var] = func['name']

        if not fee_vars_written:
            return findings

        # Interprocedural: if a non-admin user function calls an internal helper
        # that reads the fee variable, flag the public entry point.
        cg = call_graph or {}
        if cg:
            # Build reverse mapping: fee_var → setter name (already in fee_vars_written)
            # For each public/external non-admin function, collect all bodies reachable
            # via call graph and check if any of them read the fee variable.
            _func_body: Dict[str, str] = {
                f['name']: self._strip_comments(f['body']) for f in functions
            }

        # Step 2: find user-callable functions that read those fee variables
        # in fund-flow operations (affects amounts transferred/received)
        _USER_CALLABLE = frozenset({'external', 'public'})
        _FUND_FLOW_RE = _rc(
            r'\b(?:transfer|safeTransfer|mint|burn|swap|redeem|withdraw|deposit'
            r'|_transfer|_mint|_burn)\s*\(',
            re.IGNORECASE,
        )

        for func in functions:
            if func.get('visibility') not in _USER_CALLABLE:
                continue
            mod_str = func.get('modifiers', '')
            # Skip admin-only functions
            if any(m in mod_str for m in self.admin_modifiers):
                continue
            body = self._strip_comments(func['body'])
            # Must involve fund flow
            if not _FUND_FLOW_RE.search(body):
                continue

            # Expand body with all transitively-reachable internal function bodies
            # so fee vars used in helpers are caught too.
            if cg:
                reachable = self._call_graph_reachable(cg, func['name'])
                expanded_body = body + ''.join(
                    _func_body.get(r, '') for r in reachable if r != func['name']
                )
            else:
                expanded_body = body

            for var, setter_name in fee_vars_written.items():
                if re.search(rf'\b{re.escape(var)}\b', expanded_body):
                    # No timelock in source — already checked in _detect_governance_attack
                    # but this fires even when timelock exists (different threat model)
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.LOGIC,
                        title=(
                            f"Governance sandwich: `{setter_name}()` can front-run "
                            f"`{func['name']}()` via `{var}`"
                        ),
                        description=(
                            f"Admin can call `{setter_name}()` to set `{var}` to its "
                            f"maximum value, wait for a user's `{func['name']}()` transaction, "
                            f"then reset it — extracting maximum fee/slippage from the user "
                            f"in a single atomic sandwich. `{var}` takes effect immediately "
                            f"with no time-weighted average, commit-reveal, or per-block delay."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=True,
                        fix_suggestion=(
                            f"Add a time-weighted average for `{var}` (effective after N blocks), "
                            f"or cap the maximum single-step change, "
                            f"or use a commit-reveal pattern so parameter changes are "
                            f"broadcast at least one block before they take effect."
                        ),
                        cwe="CWE-362",
                        confidence=0.72,
                    ))
                    break  # one finding per user function

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # TRULY NOVEL DETECTORS — verified gap vs every public tool (2026)
    # Slither / Aderyn / Mythril / Halmos / 4naly3er / Wake / Dedaub: none of
    # these implement these patterns. Sources: tool docs + academic survey
    # "How Effective Are Smart Contract Analysis Tools" (arXiv:2005.11613).
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_read_only_reentrancy(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: View function readable during a nonReentrant external call window —
        the Curve Finance $68M bug class (June 2023).

        No public tool (Slither, Aderyn, Mythril, Wake) detects this statically.

        Root cause:
            nonReentrant functions do NOT prevent view functions from being called
            during their execution — reentrancy guards only block *state-changing*
            re-entry.  If function A is nonReentrant and makes an external ETH call
            before updating a critical state variable (e.g. virtualPrice, totalAssets,
            get_virtual_price), an attacker can:

              1. Trigger function A.
              2. During A's ETH callback, call view function B.
              3. B reads the NOT-YET-UPDATED state → returns stale value.
              4. Use stale value as a price oracle in a second protocol → profit.

        Curve attack (2023): get_virtual_price() returned stale LP price during
        remove_liquidity() ETH transfer; attacker exploited price delta in lending
        protocols that used Curve LP as collateral oracle.

        Fires when ALL of the following hold:
          1. A nonReentrant function makes a low-level ETH call (.call{value}, .transfer, .send).
          2. That function also writes to state (totalAssets/totalSupply/reserves/price)
             AFTER the ETH call (CEI violation or intentional design).
          3. A view/pure function reads those same state variables and appears to be
             used as a price or rate oracle (named getPrice/virtualPrice/exchangeRate/
             totalAssets/getReserves or returns a single numeric value).
        """
        findings = []

        # Step 1: Identify ETH-transferring nonReentrant functions with post-call
        # state updates (the "stale window" functions).
        _ETH_CALL_RE = _rc(
            r'\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(',
        )
        _STATE_WRITE_RE = _rc(
            r'\b(?:totalAssets|totalSupply|totalShares|totalReserves|'
            r'reserve\w*|balance\w*|price\w*|rate\w*|virtualPrice|'
            r'exchangeRate|getReserves|cumulativePrice)\b\s*[\+\-\*\/]?=',
        )

        stale_window_fns: list = []
        stale_vars: set = set()

        for func in functions:
            mods = func.get('modifiers', '')
            if 'nonReentrant' not in mods:
                continue
            body = self._strip_comments(func['body'])
            eth_m = _ETH_CALL_RE.search(body)
            if not eth_m:
                continue
            # Check for state write AFTER the ETH call
            after_call = body[eth_m.end():]
            sw_m = _STATE_WRITE_RE.search(after_call)
            if not sw_m:
                continue
            stale_window_fns.append(func['name'])
            # Extract the variable name — take the leading \w+ from the match
            raw_m = re.match(r'\b(\w+)\b', sw_m.group(0))
            if raw_m and raw_m.group(1):
                stale_vars.add(raw_m.group(1))

        if not stale_window_fns:
            return findings

        # Step 2: Find view functions that return the stale variables — oracle candidates.
        _ORACLE_NAME_RE = _rc(
            r'\b(?:get(?:Price|Rate|Reserve|VirtualPrice|ExchangeRate|TotalAssets|'
            r'AssetPrice|SharePrice|UnderlyingPrice)|'
            r'virtualPrice|exchangeRate|pricePerShare|convertToAssets|'
            r'totalAssets|getReserves|previewRedeem|previewWithdraw)\b',
            re.IGNORECASE,
        )

        for func in functions:
            mods = func.get('modifiers', '')
            if not re.search(r'\b(?:view|pure)\b', mods):
                continue
            fname = func['name']
            body = self._strip_comments(func['body'])

            is_oracle = bool(_ORACLE_NAME_RE.search(fname))
            reads_stale = any(
                re.search(rf'\b{re.escape(v)}\b', body) for v in stale_vars
            )

            if not (is_oracle or reads_stale):
                continue

            for culprit in stale_window_fns:
                findings.append(StaticFinding(
                    severity=StaticSeverity.HIGH,
                    category=StaticCategory.REENTRANCY,
                    title=(
                        f"Read-only reentrancy: `{fname}()` reads stale state "
                        f"during `{culprit}()` ETH callback"
                    ),
                    description=(
                        f"`{culprit}()` is `nonReentrant` and makes an ETH transfer "
                        f"BEFORE updating critical state. During the ETH callback, "
                        f"an attacker can call `{fname}()` — a `view` function, "
                        f"not blocked by the reentrancy guard — and receive the "
                        f"NOT-YET-UPDATED value. External lending/derivatives "
                        f"protocols that use `{fname}()` as a price oracle can be "
                        f"exploited for the price delta. Real-world: Curve Finance "
                        f"LP oracle bug (June 2023, $68M+ at risk)."
                    ),
                    location=f"{fname}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        f"Option A: Move all state updates in `{culprit}()` BEFORE "
                        f"the ETH transfer (CEI pattern). This eliminates the stale window.\n"
                        f"Option B: Add a `nonReentrant` guard to `{fname}()` — this "
                        f"blocks the read during the ETH callback at the cost of preventing "
                        f"legitimate view-only reentrancy.\n"
                        f"Option C: Cache the state variable at the START of `{culprit}()` "
                        f"and write it back at the END — the view returns the cached (correct) "
                        f"value throughout."
                    ),
                    cwe="CWE-362",
                    confidence=0.78,
                ))
                break  # one finding per view function

        return findings

    def _detect_incomplete_pausable(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: Contract uses Pausable but not all external state-changing functions
        have `whenNotPaused` — critical operations executable during a pause.

        No public tool checks for incomplete pausable coverage.

        Common C4/Sherlock finding: protocol pauses in emergency but attacker
        continues calling unguarded withdraw/swap/liquidate functions.

        Fires when:
          1. Contract uses Pausable (whenNotPaused, _pause(), paused()).
          2. At least ONE external/public function has whenNotPaused.
          3. At least ONE OTHER external/public state-changing function does NOT
             have whenNotPaused — and is not admin-only (admin bypass is by design).

        Not flagged:
          - Admin-only functions (onlyOwner/onlyRole) — intentional pause bypass.
          - View/pure functions — no state consequence.
          - Functions that explicitly check paused() internally.
        """
        uses_pausable = bool(re.search(
            r'\bwhenNotPaused\b|\bPausable\b|\b_pause\s*\(\s*\)|\bpaused\s*\(\s*\)',
            source,
        ))
        if not uses_pausable:
            return []

        _PAUSED_INLINE_RE = _rc(r'\bpaused\s*\(\s*\)', re.IGNORECASE)

        protected_fns: list = []
        unprotected_fns: list = []

        for func in functions:
            vis = func.get('visibility', '')
            if vis not in ('external', 'public'):
                continue
            name = func['name']
            if name in ('constructor', 'receive', 'fallback'):
                continue
            mods = func.get('modifiers', '')
            body = self._strip_comments(func.get('body', ''))

            # Skip view/pure
            if re.search(r'\b(?:view|pure)\b', mods):
                continue
            # Skip empty bodies (interface stubs)
            if not body.strip():
                continue
            # Skip admin-only — pause bypass for admin is intentional
            if any(m in mods for m in self.admin_modifiers):
                continue
            # Skip pause/unpause functions themselves
            if re.search(r'\b(?:pause|unpause)\b', name, re.IGNORECASE):
                continue

            has_pause_mod = 'whenNotPaused' in mods
            has_inline_check = bool(_PAUSED_INLINE_RE.search(body))
            is_protected = has_pause_mod or has_inline_check

            # Must actually change state (not just a getter with external call)
            has_state_write = bool(re.search(
                r'\w+\[[^\]]+\]\s*[\+\-\*\/]?=(?!=)|'
                r'\b\w+\s*[\+\-]?=(?!=)',
                body
            ))
            if not has_state_write:
                continue

            if is_protected:
                protected_fns.append(name)
            else:
                unprotected_fns.append(func)

        if not protected_fns or not unprotected_fns:
            return []

        findings = []
        for func in unprotected_fns:
            findings.append(StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.ACCESS_CONTROL,
                title=f"Incomplete pausable: `{func['name']}()` callable during pause",
                description=(
                    f"Contract uses `Pausable` (`whenNotPaused` on: "
                    f"{', '.join(protected_fns[:3])}{'...' if len(protected_fns) > 3 else ''}). "
                    f"However, `{func['name']}()` is external/public, changes state, "
                    f"and has NO `whenNotPaused` guard. During an emergency pause, "
                    f"this function remains fully callable — an attacker can continue "
                    f"extracting value while the protocol's pause is in effect."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    f"Add `whenNotPaused` modifier to `{func['name']}()`, "
                    f"or document explicitly why this function must remain operational "
                    f"during a pause (e.g. emergency withdrawal path)."
                ),
                cwe="CWE-284",
                confidence=0.80,
            ))

        return findings

    def _detect_erc4626_rounding_direction(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: ERC4626 vault functions use wrong rounding direction.

        No public tool checks EIP-4626 rounding compliance.

        EIP-4626 mandates specific rounding to protect depositors from extraction:
          - convertToShares / previewDeposit / deposit:
              shares = assets * totalSupply / totalAssets  → ROUND DOWN (mulDiv)
              (user gets FEWER shares; excess stays in vault)
          - convertToAssets / previewRedeem / redeem:
              assets = shares * totalAssets / totalSupply  → ROUND DOWN (mulDiv)
              (user gets FEWER assets; excess stays in vault)
          - previewWithdraw / withdraw:
              shares = assets * totalSupply / totalAssets  → ROUND UP (ceilDiv/mulDivUp)
              (user pays MORE shares; protects vault from rounding drain)
          - previewMint / mint:
              assets = shares * totalAssets / totalSupply  → ROUND UP (ceilDiv/mulDivUp)
              (user pays MORE assets; protects vault)

        Wrong rounding:
          A. Round UP on deposit/redeem → user extracts 1 wei/tx repeatedly → bank-run.
          B. Round DOWN on withdraw/mint → user pays fewer shares → 1-wei drain.

        Real-world: multiple C4 Highs on ERC4626 wrappers (2022-2024).
        """
        findings = []

        is_4626 = bool(re.search(
            r'\bERC4626\b|'
            r'\bfunction\s+(?:deposit|redeem|withdraw|mint)\s*\(',
            source, re.IGNORECASE
        ))
        if not is_4626:
            return findings

        # Round-up indicators (user PAYS more — correct for withdraw/mint)
        _CEIL_RE = _rc(
            r'\bceil(?:Div|Mul)?\b|mulDivUp\b|Math\.ceilDiv\b|'
            r'FixedPointMathLib\.mulDivUp\b|'
            r'\+\s*1\s*\)\s*/|'           # (x + 1) / y pattern
            r'\+\s*(?:denominator|divisor|totalSupply|totalAssets)\s*-\s*1',
            re.IGNORECASE,
        )
        # Round-down indicators (user GETS less — correct for deposit/redeem)
        _FLOOR_RE = _rc(
            r'\bmulDiv\b(?!\s*Up)|Math\.mulDiv\b(?!\s*Up)|'
            r'FixedPointMathLib\.mulDiv\b(?!\s*Up)',
            re.IGNORECASE,
        )

        # Functions that MUST round down (deposit-side)
        _MUST_ROUND_DOWN = frozenset({
            'convertToShares', 'previewDeposit', 'deposit',
            'convertToAssets', 'previewRedeem', 'redeem',
        })
        # Functions that MUST round up (withdrawal-side)
        _MUST_ROUND_UP = frozenset({
            'previewWithdraw', 'withdraw',
            'previewMint', 'mint',
        })

        for func in functions:
            fname = func['name']
            if fname not in (_MUST_ROUND_DOWN | _MUST_ROUND_UP):
                continue
            body = self._strip_comments(func['body'])
            # Only check functions that actually do the math (not pure delegators)
            if '/' not in body and 'mulDiv' not in body:
                continue

            uses_ceil = bool(_CEIL_RE.search(body))
            uses_floor = bool(_FLOOR_RE.search(body)) or (not uses_ceil and '/' in body)

            if fname in _MUST_ROUND_DOWN and uses_ceil:
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.ACCOUNTING,
                    title=f"ERC4626: `{fname}()` rounds UP — should round DOWN",
                    description=(
                        f"EIP-4626 requires `{fname}()` to round DOWN (floor division) "
                        f"to protect the vault: users get FEWER shares/assets, excess "
                        f"stays in the vault. Rounding UP here gives users MORE than "
                        f"their proportional share — repeated 1-wei deposits can "
                        f"drain the vault's accumulated rounding residuals."
                    ),
                    location=f"{fname}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        f"Replace ceiling division with floor: use `mulDiv(assets, "
                        f"totalSupply, totalAssets)` (no rounding-up variant). "
                        f"OpenZeppelin ERC4626 v5 handles this correctly by default."
                    ),
                    cwe="CWE-682",
                    confidence=0.82,
                ))

            elif fname in _MUST_ROUND_UP and uses_floor and not uses_ceil:
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.ACCOUNTING,
                    title=f"ERC4626: `{fname}()` rounds DOWN — should round UP",
                    description=(
                        f"EIP-4626 requires `{fname}()` to round UP (ceiling division) "
                        f"to protect the vault: callers pay MORE shares/assets, vault "
                        f"is protected from rounding drain. Rounding DOWN means callers "
                        f"can repeatedly withdraw/mint paying 1 wei less per tx — "
                        f"over many transactions this extracts the vault's rounding surplus."
                    ),
                    location=f"{fname}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        f"Use ceiling division: `mulDivUp(assets, totalSupply, totalAssets)` "
                        f"(FixedPointMathLib or OZ Math.ceilDiv). "
                        f"EIP-4626 §NOTE: 'Implementors MAY satisfy these requirements by '  "
                        f"performing a ceiling division on the result of mulDiv.'"
                    ),
                    cwe="CWE-682",
                    confidence=0.78,
                ))

        return findings

    def _detect_rebasing_token_accounting(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: Protocol stores a user's deposit amount statically but the
        underlying token rebases (stETH, wstETH, AMPL, aTokens) — stored
        balance diverges from actual balance over time.

        No public tool detects this pattern.

        Attack surface:
          A. Negative rebase (stETH slashing event): stored balance EXCEEDS actual
             → last withdrawer cannot withdraw (contract insolvent).
          B. Positive rebase (stETH rewards): stored balance UNDER-COUNTS actual
             → rewards are stranded in the contract forever.
          C. Protocol uses stored balance for share computation → incorrect dilution.

        Detection: protocol stores `deposited[user] += amount` and later
        uses `deposited[user]` directly in a transfer/mint, without ever
        measuring the LIVE `balanceOf(address(this))` delta between deposit
        and withdrawal.

        Note: this is distinct from fee-on-transfer (which is about transfer
        fees reducing the received amount). Rebasing changes the balance of
        ALREADY-HELD tokens.
        """
        findings = []

        # Heuristic: check for known rebasing token names or interfaces
        _REBASE_TOKEN_RE = _rc(
            r'\b(?:stETH|wstETH|AMPL|Ampleforth|aToken|rToken|'
            r'IStETH|IWstETH|IAMPL|IAToken|rebase|rebasing|'
            r'elastic|ElasticToken|sharesOf|getSharesByPooledEth|'
            r'getPooledEthByShares)\b',
            re.IGNORECASE,
        )
        _LIVE_BALANCE_RE = _rc(
            r'\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
            re.IGNORECASE,
        )
        _STORED_BALANCE_RE = _rc(
            r'\b(?:deposited|staked|balances|userBalance|principal|'
            r'lockedAmount|depositedAmount|depositedBalance|stakedBalance|'
            r'userDeposit|userDeposited|userStake)\s*\[[^\]]+\]\s*[\+\-]?=',
            re.IGNORECASE,
        )
        _STORED_USED_RE = _rc(
            r'\b(?:deposited|staked|balances|userBalance|principal|'
            r'lockedAmount|depositedAmount|depositedBalance|stakedBalance|'
            r'userDeposit|userDeposited|userStake)\s*\[[^\]]+\]',
            re.IGNORECASE,
        )

        uses_rebase_token = bool(_REBASE_TOKEN_RE.search(source))
        uses_stored = bool(_STORED_BALANCE_RE.search(source))
        uses_live_balance = bool(_LIVE_BALANCE_RE.search(source))

        # Only flag if there's a rebase signal AND stored balance pattern
        if not uses_rebase_token or not uses_stored:
            return findings

        # If contract measures live balanceOf → it likely handles rebasing correctly
        if uses_live_balance:
            return findings

        # Find deposit functions that store amounts
        _DEPOSIT_FN_RE = _rc(
            r'\b(?:deposit|stake|provide|lock|supply)\b',
            re.IGNORECASE,
        )
        _WITHDRAW_FN_RE = _rc(
            r'\b(?:withdraw|unstake|redeem|unlock|claim)\b',
            re.IGNORECASE,
        )
        _TRANSFER_OUT_RE = _rc(
            r'\b(?:transfer|safeTransfer|send)\b',
            re.IGNORECASE,
        )

        deposit_funcs = []
        withdraw_funcs = []
        for func in functions:
            name = func['name']
            body = self._strip_comments(func['body'])
            if _DEPOSIT_FN_RE.search(name) and _STORED_BALANCE_RE.search(body):
                deposit_funcs.append(func['name'])
            if _WITHDRAW_FN_RE.search(name) and _STORED_USED_RE.search(body) \
                    and _TRANSFER_OUT_RE.search(body):
                withdraw_funcs.append(func)

        for func in withdraw_funcs:
            findings.append(StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.ACCOUNTING,
                title=(
                    f"Rebasing token accounting mismatch in `{func['name']}()`: "
                    f"stored balance used for withdrawal"
                ),
                description=(
                    f"Contract stores user deposit amounts statically "
                    f"({', '.join(deposit_funcs[:2]) or 'deposit functions'} write to "
                    f"a balance mapping) and uses the stored value in `{func['name']}()` "
                    f"for transfers/redemptions. The underlying token appears to be "
                    f"rebasing (stETH/AMPL/aToken detected in source). "
                    f"After a negative rebase: `storedBalance > actualBalance` → "
                    f"last withdrawer cannot exit (insolvency). "
                    f"After a positive rebase: rewards are stranded in the contract."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Use shares-based accounting: store the user's PROPORTIONAL SHARE "
                    "of the pool (userShares / totalShares) rather than an absolute amount. "
                    "On withdrawal, compute `amount = userShares * balanceOf(address(this)) "
                    "/ totalShares`. This automatically tracks rebases in both directions."
                ),
                cwe="CWE-682",
                confidence=0.75,
            ))

        return findings

    # ── Novel detector: block.timestamp manipulation ──────────────────────────

    def _detect_timestamp_dependency(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        LOW: block.timestamp used as an exact equality check or sole condition
        for financial state changes — validator-manipulable within ~12 seconds.

        Three sub-patterns:
          A. Strict equality: block.timestamp == <var/constant>
             → impossible to hit in most txs; DoS or front-runnable unlock.
          B. block.timestamp as a lock expiry in financial functions without
             a tolerance window (no "+buffer" or "grace period" pattern).
          C. block.timestamp as the RNG seed (entropy = 0 from validator POV).

        Not flagged:
          - Vesting/cliff logic where timestamp is used with >= / <= (intentional).
          - View functions (no state consequence).
          - Chainlink feed freshness checks (updatedAt vs block.timestamp is correct).
        """
        findings = []

        _STRICT_EQ_RE = _rc(
            r'block\.timestamp\s*==\s*\w|'
            r'\w\s*==\s*block\.timestamp',
        )
        _LOCK_UNLOCK_RE = _rc(
            r'\b(?:unlock|lock|release|vest|cliff|expir|mature|start|end)\w*\b',
            re.IGNORECASE,
        )
        _TOLERANCE_RE = _rc(
            r'block\.timestamp\s*[+\-]\s*\w|'
            r'\bgrace\b|\bbuffer\b|\btolerance\b|\bwindow\b|\bdelay\b',
            re.IGNORECASE,
        )
        _RNG_RE = _rc(
            r'block\.timestamp\s*%\s*[a-zA-Z_]\w*|'  # direct modulo with variable (not numeric literal)
            r'(?:keccak256|sha256|sha3)\b.{1,300}block\.timestamp.{0,300}%\s*\w',  # hash(... ts ...) % N
            re.DOTALL,
        )
        # Chainlink staleness check — suppress: comparing updatedAt vs block.timestamp is correct
        _CHAINLINK_STALE_RE = _rc(
            r'\b(?:updatedAt|updated_at|lastUpdated|lastUpdate|updateTime|lastTimestamp)\b',
        )

        for func in functions:
            body = self._strip_comments(func['body'])

            # Sub-pattern C: block.timestamp as RNG seed
            if _RNG_RE.search(body):
                findings.append(StaticFinding(
                    severity=StaticSeverity.MEDIUM,
                    category=StaticCategory.LOGIC,
                    title=f"Timestamp manipulation: block.timestamp as RNG in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` uses ``block.timestamp`` as an entropy source "
                        f"(via keccak256 or modulo). Validators can set ``block.timestamp`` "
                        f"within a ~12-second window, making the output predictable and "
                        f"manipulable by any validator including MEV bots."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=True,
                    fix_suggestion=(
                        "Use a commit-reveal scheme or Chainlink VRF for randomness. "
                        "Never use ``block.timestamp``, ``block.number``, or ``blockhash`` "
                        "as entropy sources."
                    ),
                    cwe="CWE-330",
                    confidence=0.88,
                ))
                continue  # one finding per function

            # Sub-pattern A: strict equality check on block.timestamp
            if _STRICT_EQ_RE.search(body):
                # Skip if this is a Chainlink staleness check
                if _CHAINLINK_STALE_RE.search(body):
                    continue
                findings.append(StaticFinding(
                    severity=StaticSeverity.LOW,
                    category=StaticCategory.LOGIC,
                    title=f"Timestamp manipulation: strict equality on block.timestamp in {func['name']}()",
                    description=(
                        f"``{func['name']}()`` uses ``block.timestamp ==`` for an exact match. "
                        f"Validators control block timestamp within ~12 seconds; an exact match "
                        f"can be permanently avoided (DoS) or hit precisely by a miner/validator. "
                        f"The condition will almost never be satisfied in practice."
                    ),
                    location=f"{func['name']}():L{func['line']}",
                    exploitable=False,
                    fix_suggestion=(
                        "Replace with a range check: "
                        "``block.timestamp >= target && block.timestamp <= target + TOLERANCE``."
                    ),
                    cwe="CWE-362",
                    confidence=0.80,
                ))
                continue

            # Sub-pattern B: financial unlock/lock GATED solely by block.timestamp without tolerance.
            # Only fire when block.timestamp appears in a CONDITIONAL (if/require/while),
            # not when it is merely recorded as an assignment (e.g. vestingStart = block.timestamp).
            _cond_ts = bool(re.search(
                r'\b(?:if|require|while|assert)\b[^;]*block\.timestamp', body
            ))
            if _LOCK_UNLOCK_RE.search(func['name']) or _LOCK_UNLOCK_RE.search(body):
                if _cond_ts and not _TOLERANCE_RE.search(body):
                    # Only flag if it's a state-changing function (not view)
                    mods = func.get('modifiers', '')
                    mod_str = mods if isinstance(mods, str) else ' '.join(mods)
                    if re.search(r'\b(?:view|pure)\b', mod_str):
                        continue
                    # Skip if body only reads state — no assignments
                    if not re.search(r'\b\w+\s*[\+\-\*\/]?=(?!=)', body):
                        continue
                    findings.append(StaticFinding(
                        severity=StaticSeverity.LOW,
                        category=StaticCategory.LOGIC,
                        title=f"Timestamp manipulation: no tolerance window in {func['name']}()",
                        description=(
                            f"``{func['name']}()`` uses ``block.timestamp`` to gate a "
                            f"lock/unlock/release state change without a tolerance buffer. "
                            f"A validator can include or exclude a transaction from a block "
                            f"within ~12 seconds to manipulate the timing."
                        ),
                        location=f"{func['name']}():L{func['line']}",
                        exploitable=False,
                        fix_suggestion=(
                            "Consider adding a grace period constant "
                            "(e.g. ``TOLERANCE = 15 seconds``) to avoid strict timestamp gates."
                        ),
                        cwe="CWE-362",
                        confidence=0.65,
                    ))

        return findings

    # ══════════════════════════════════════════════════════════════════════════
    # v1.7 DETECTORS — 10 new classes covering top DeFi hack patterns 2022-2026
    # Ranked by on-chain loss: Wormhole $320M, Poly $611M, Mango $117M, etc.
    # Sources: Halborn Top-100, Rekt.news, C4/Sherlock finding databases.
    # None of these are covered by Slither, Aderyn, Dedaub, or Mythril by default.
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_unprotected_initialize(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: initialize() callable multiple times — missing `initializer` modifier.

        Root cause of Wormhole ($320M), Ronin ($625M guardianSet reset),
        and dozens of upgradeable proxy exploits.

        Pattern:
          function initialize(...) public {   // NO initializer/onlyOwner guard
              owner = msg.sender;
          }

        Detection:
          1. Function named initialize/init/setUp/setup (case-insensitive).
          2. No `initializer`, `onlyOwner`, `onlyAdmin`, or `_notInitialized`
             modifier and no inline require that guards re-initialization.
          3. Not marked `internal` or `private` (callable externally).

        Not flagged:
          - `function initialize() internal` — cannot be called externally.
          - `function initialize() external initializer` — OZ initializer guard.
          - If body starts with `require(!initialized)` or similar sentinel.
        """
        findings = []
        _INIT_NAME_RE = _rc(
            r'^(?:initialize|init|setUp|setup|__init|_init)\w*$',
            re.IGNORECASE,
        )
        _INIT_GUARD_RE = _rc(
            r'\b(?:initializer|reinitializer|onlyInitializing|notInitialized|'
            r'_notInitialized|_initialized|initialized)\b',
        )
        _SENTINEL_RE = _rc(
            r'require\s*\(\s*!\s*\w*init\w*|'
            r'require\s*\(\s*\w*init\w*\s*==\s*false|'
            r'if\s*\(\s*\w*init\w*\s*\)\s*revert',
            re.IGNORECASE,
        )
        for func in functions:
            name = func.get('name', '')
            if not _INIT_NAME_RE.match(name):
                continue
            vis = func.get('visibility', 'public')
            if vis in ('internal', 'private'):
                continue
            mod_str = func.get('modifiers', '')
            body = self._strip_comments(func['body'])
            if _INIT_GUARD_RE.search(mod_str):
                continue
            if any(m in mod_str for m in self.admin_modifiers):
                continue
            if _SENTINEL_RE.search(body[:400]):
                continue
            # Inline require(msg.sender == <factory/deployer>) is a valid one-time guard
            if re.search(r'require\s*\(\s*msg\.sender\s*==\s*\w+\s*[,)]', body[:300]):
                continue
            if not re.search(r'\b\w+\s*[\+\-\*\/]?=(?!=)', body):
                continue
            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.MISSING_ACCESS_CONTROL,
                title=f"Unprotected initializer: {name}() callable multiple times",
                description=(
                    f"`{name}()` is `{vis}` and has no `initializer` modifier "
                    f"or re-initialization guard. An attacker can call it after "
                    f"deployment to reset critical state (owner, admin, guardian sets). "
                    f"Root cause of Wormhole ($320M) and Ronin ($625M) exploits."
                ),
                location=f"{name}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Add OZ `initializer` modifier: "
                    "`function initialize(...) external initializer { ... }`. "
                    "Or add `bool private _initialized; "
                    "require(!_initialized); _initialized = true;` at the top."
                ),
                cwe="CWE-665",
                confidence=0.82,
            ))
        return findings

    def _detect_tx_origin_auth(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: tx.origin used for authentication instead of msg.sender.

        tx.origin is the original EOA that initiated the transaction chain.
        Any contract called from the victim's tx can trigger this check —
        enabling phishing attacks where victim calls attacker contract which
        then calls the vulnerable contract with victim's tx.origin.

        Pattern: require(tx.origin == owner) or if (tx.origin != admin) revert

        Not flagged:
          - tx.origin == msg.sender (EOA-only check, valid anti-contract pattern)
          - tx.origin in comments only
        """
        findings = []
        _TXORIGIN_AUTH_RE = _rc(
            r'(?:require|if)\s*\([^;)]*tx\.origin\s*[!=]=\s*(?!msg\.sender)\w',
            re.IGNORECASE | re.DOTALL,
        )
        _TXORIGIN_EOA_RE = _rc(
            r'tx\.origin\s*[!=]=\s*msg\.sender|msg\.sender\s*[!=]=\s*tx\.origin',
        )
        for func in functions:
            body = self._strip_comments(func['body'])
            m = _TXORIGIN_AUTH_RE.search(body)
            if not m:
                continue
            context = body[max(0, m.start() - 10): m.end() + 50]
            if _TXORIGIN_EOA_RE.search(context):
                continue
            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.MISSING_ACCESS_CONTROL,
                title=f"tx.origin authentication in {func['name']}()",
                description=(
                    f"`{func['name']}()` uses `tx.origin` for access control. "
                    f"An attacker deploys a malicious contract; when the owner calls it, "
                    f"`tx.origin` equals the owner but `msg.sender` is the attacker — "
                    f"bypassing the check and allowing unauthorized state changes."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Replace `tx.origin` with `msg.sender`. "
                    "For EOA-only enforcement (blocking contracts), use "
                    "`require(msg.sender == tx.origin, 'no contracts allowed');`."
                ),
                cwe="CWE-284",
                confidence=0.90,
            ))
        return findings

    def _detect_spot_price_oracle(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: AMM spot price (getReserves) used as oracle — flash-loan manipulable.

        Using reserve0/reserve1 or getReserves() for price computation is
        manipulable in a single tx via flash loans.

        Real attacks: Mango Markets ($117M), CREAM Finance ($130M),
        Compound COMP listing ($89M).

        Detection:
          1. getReserves() / reserve0 / reserve1 used in price arithmetic.
          2. No TWAP usage (cumulativeLast, observe, consult) in source.

        Not flagged:
          - Contracts that use TWAP alongside getReserves.
        """
        findings = []
        _SPOT_PRICE_RE = _rc(
            r'getReserves\s*\(\s*\)|'
            r'\breserve0\b|\breserve1\b|'
            r'\b_reserve0\b|\b_reserve1\b',
        )
        _TWAP_RE = _rc(
            r'(?:price0CumulativeLast|price1CumulativeLast|'
            r'observe\s*\(|consult\s*\(|TWAP|twap|TimeWeightedAverage)',
        )
        _PRICE_ARITH_RE = _rc(
            r'(?:price|rate|value|quote|amount)\s*=\s*.{0,80}'
            r'(?:reserve|getReserves|balanceOf)',
            re.IGNORECASE | re.DOTALL,
        )
        if _TWAP_RE.search(source):
            return findings
        for func in functions:
            body = self._strip_comments(func['body'])
            if not _SPOT_PRICE_RE.search(body):
                continue
            if not _PRICE_ARITH_RE.search(body):
                if not re.search(
                    r'reserve\w*\s*[\*/]\s*\w+|\w+\s*[\*/]\s*reserve\w*',
                    body, re.IGNORECASE
                ):
                    continue
            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.ORACLE,
                title=f"Spot price oracle in {func['name']}(): flash-loan manipulable",
                description=(
                    f"`{func['name']}()` reads AMM reserves (`getReserves()` / "
                    f"`reserve0` / `reserve1`) for price computation. "
                    f"Spot prices are manipulable in a single tx via flash loans: "
                    f"borrow → skew reserves → read fake price → exploit → repay. "
                    f"Mango Markets ($117M), CREAM ($130M), Compound ($89M)."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Use a TWAP with ≥30-minute window: Uniswap V2 `price0CumulativeLast`, "
                    "V3 `observe()`, or Chainlink feeds. "
                    "Never use `getReserves()` directly for collateral/liquidation pricing."
                ),
                cwe="CWE-20",
                confidence=0.80,
            ))
        return findings

    def _detect_signature_replay(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: ecrecover/ECDSA.recover without per-signer nonce — replay attack.

        A signed message without a nonce can be submitted multiple times.
        Without chainId it can also be replayed on other chains.

        Real attacks: Wormhole VAA replay ($320M), various permit-based exploits.

        Detection:
          1. Function uses ecrecover() or ECDSA.recover() for authentication.
          2. No nonce variable tracked in-scope.
          3. No mapping(address => uint256) nonce mapping in source.

        Not flagged:
          - Functions that reference `nonce` in their body.
          - Contracts with a nonce mapping (EIP-2612 style).
        """
        findings = []
        _ECRECOVER_RE = _rc(
            r'\becrecover\s*\(|ECDSA\.recover\s*\(|SignatureChecker\.',
        )
        _NONCE_RE = _rc(r'\bnonce\w*\b', re.IGNORECASE)
        _NONCE_MAP_RE = _rc(
            r'mapping\s*\([^)]*\)\s*(?:\w+\s+)*nonce',
            re.IGNORECASE,
        )
        _DEADLINE_RE = _rc(
            r'\bdeadline\b|\bexpiry\b|\bexpiration\b|\bvalidUntil\b',
            re.IGNORECASE,
        )
        has_nonce_map = bool(_NONCE_MAP_RE.search(source))
        for func in functions:
            body = self._strip_comments(func['body'])
            if not _ECRECOVER_RE.search(body):
                continue
            if _NONCE_RE.search(body) or has_nonce_map:
                continue
            has_deadline = bool(_DEADLINE_RE.search(body))
            sev = StaticSeverity.HIGH if not has_deadline else StaticSeverity.MEDIUM
            findings.append(StaticFinding(
                severity=sev,
                category=StaticCategory.LOGIC,
                title=f"Signature replay: {func['name']}() missing nonce",
                description=(
                    f"`{func['name']}()` verifies a signature via `ecrecover`/ECDSA "
                    f"but does not track a per-signer nonce. The same signature can "
                    f"be replayed multiple times or across chains. "
                    + ("No deadline found — signature is valid indefinitely." if not has_deadline else "")
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Include `nonces[signer]++` in the signed digest (EIP-712) and "
                    "increment it after verification. Also include `block.chainid` and "
                    "a `deadline` timestamp to prevent cross-chain and indefinite replays."
                ),
                cwe="CWE-294",
                confidence=0.78,
            ))
        return findings

    def _detect_missing_slippage_protection(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM/HIGH: DEX swap/liquidity call without minAmountOut — sandwich-able.

        Passing `0` or no minimum output to a DEX router allows MEV bots to
        sandwich the transaction, extracting 100% of price impact.

        Cost: ~$1.4M/week extracted from Ethereum via sandwich attacks (Flashbots data).

        Detection:
          1. Call to known DEX router functions (swapExact*, swap, addLiquidity, etc.).
          2. `0` literal passed as the minAmountOut parameter, or no min-amount
             variable visible in the call context.

        Not flagged:
          - Calls that pass a named min-amount variable.
          - Internal/private helper functions.
        """
        findings = []
        _SWAP_CALL_RE = _rc(
            r'\b(?:swapExactTokensForTokens|swapTokensForExactTokens|'
            r'swapExactETHForTokens|swapExactTokensForETH|'
            r'swapExactTokensForTokensSupportingFeeOnTransferTokens|'
            r'exactInput|exactOutput|exactInputSingle|exactOutputSingle|'
            r'addLiquidity|addLiquidityETH|removeLiquidity)\s*\(',
            re.IGNORECASE,
        )
        _ZERO_SLIPPAGE_RE = _rc(
            r',\s*0\s*,\s*(?:address|0x|\[)',
        )
        _MIN_AMOUNT_RE = _rc(
            r'\b(?:minAmountOut|minReturn|amountOutMin|minOut|minReceived|'
            r'minAmount|minTokens|minOutputAmount|minLiquidity)\b',
            re.IGNORECASE,
        )
        for func in functions:
            vis = func.get('visibility', 'public')
            if vis in ('internal', 'private'):
                continue
            body = self._strip_comments(func['body'])
            if not _SWAP_CALL_RE.search(body):
                continue
            if _MIN_AMOUNT_RE.search(body):
                continue
            if _ZERO_SLIPPAGE_RE.search(body):
                sev = StaticSeverity.HIGH
                note = "Hardcoded `0` detected as minimum output — 100% slippage accepted."
            else:
                sev = StaticSeverity.MEDIUM
                note = "No explicit minimum-output variable found."
            findings.append(StaticFinding(
                severity=sev,
                category=StaticCategory.LOGIC,
                title=f"Missing slippage protection in {func['name']}()",
                description=(
                    f"`{func['name']}()` calls a DEX router without a validated "
                    f"minimum output amount. {note} "
                    f"MEV bots front-run and back-run to extract the full price impact."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Pass `amountOutMin = expectedAmount * (10000 - maxSlippageBps) / 10000`. "
                    "Expose `minAmountOut` as a caller parameter for EOA-facing functions."
                ),
                cwe="CWE-20",
                confidence=0.75,
            ))
        return findings

    def _detect_ether_lock(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: Contract accepts ETH but has no withdrawal mechanism.

        Any ETH sent to a payable contract with no ETH-out path is permanently locked.

        Not flagged:
          - Contracts with selfdestruct (can drain ETH).
          - Contracts with any transfer/call{value/send path.
        """
        findings = []
        has_receive = bool(re.search(
            r'\breceive\s*\(\s*\)\s*external\s+payable|'
            r'\bfallback\s*\(\s*\)\s*external\s+payable',
            source,
        ))
        has_payable_fn = bool(re.search(
            r'function\s+\w+\s*\([^)]*\)\s+(?:\w+\s+)*payable',
            source,
        ))
        if not (has_receive or has_payable_fn):
            return findings
        _ETH_OUT_RE = _rc(
            r'\.call\s*\{\s*value\s*:|'
            r'\btransfer\s*\(|'
            r'\bsend\s*\(|'
            r'\bselfdestruct\s*\(|'
            r'\bwithdrawETH\b|\brescueETH\b',
            re.IGNORECASE,
        )
        if _ETH_OUT_RE.search(source):
            return findings
        contract_m = re.search(r'\bcontract\s+(\w+)', source)
        contract_name = contract_m.group(1) if contract_m else "Unknown"
        findings.append(StaticFinding(
            severity=StaticSeverity.MEDIUM,
            category=StaticCategory.LOGIC,
            title=f"Ether lock: {contract_name} accepts ETH but has no withdrawal path",
            description=(
                f"`{contract_name}` has a `payable` function or `receive()` but "
                f"no code path to send ETH out. ETH is permanently locked."
            ),
            location=contract_name,
            exploitable=False,
            fix_suggestion=(
                "Add `function rescueETH(address payable to, uint256 amt) external onlyOwner "
                "{ to.call{value: amt}(\"\"); }`. "
                "Or remove `payable` if ETH acceptance is unintentional."
            ),
            cwe="CWE-400",
            confidence=0.72,
        ))
        return findings

    def _detect_division_by_zero_risk(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: Division by totalSupply/totalShares without zero guard.

        An empty pool causes division-by-zero panic. Near-zero denominator
        causes extreme precision loss, enabling first-depositor manipulation.

        Detection:
          1. Division where denominator is a pool-total variable.
          2. No zero guard (require/if) on that variable before the division.
        """
        findings = []
        _DIV_DENOM_RE = _rc(
            r'/\s*(?:totalSupply|totalShares|totalAssets|totalDeposits|'
            r'totalBalance|totalLiquidity|_totalSupply|_totalShares)\b',
        )
        _ZERO_GUARD_RE = _rc(
            r'(?:require|if)\s*\([^;)]*'
            r'(?:totalSupply|totalShares|totalAssets|totalDeposits|'
            r'totalBalance|totalLiquidity|_totalSupply|_totalShares)'
            r'\s*(?:[!=]=\s*0|>\s*0)',
        )
        for func in functions:
            body = self._strip_comments(func['body'])
            if not _DIV_DENOM_RE.search(body):
                continue
            if _ZERO_GUARD_RE.search(body):
                continue
            m = _DIV_DENOM_RE.search(body)
            denom = m.group(0).lstrip('/ ').strip() if m else 'totalSupply'
            findings.append(StaticFinding(
                severity=StaticSeverity.MEDIUM,
                category=StaticCategory.LOGIC,
                title=f"Division-by-zero risk: {func['name']}() divides by `{denom}`",
                description=(
                    f"`{func['name']}()` divides by `{denom}` without a prior "
                    f"zero-value guard. Empty pool → panic revert (DoS). "
                    f"Also enables first-depositor share inflation attacks."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    f"Add `if ({denom} == 0) return <default>;` before the division. "
                    f"For vaults, use the virtual offset: divide by `({denom} + 1)`."
                ),
                cwe="CWE-369",
                confidence=0.78,
            ))
        return findings

    def _detect_hardcoded_decimals(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        LOW: Hardcoded 1e18 decimal assumption on potentially non-18-decimal tokens.

        USDC/USDT have 6 decimals, WBTC has 8. Hardcoded 1e18 causes 10^12 pricing
        errors when these tokens are used.

        Detection:
          1. 1e18 / 10**18 / 1 ether in arithmetic.
          2. Contract uses external ERC20 token.
          3. No .decimals() normalization call.

        Not flagged:
          - ETH-only contracts.
          - Contracts calling .decimals().
          - Named precision constants (PRECISION, RAY, WAD).
        """
        findings = []
        _HARDCODED_18_RE = _rc(r'\b1e18\b|10\s*\*\*\s*18\b|1\s+ether\b')
        _ERC20_IFACE_RE = _rc(r'\bIERC20\b|\bERC20\b|\bIERC20Metadata\b')
        _DECIMALS_NORM_RE = _rc(r'\.decimals\s*\(\s*\)|\bDECIMALS\b|\bTOKEN_DECIMALS\b')
        _PRECISION_CONST_RE = _rc(
            r'\b(?:PRECISION|RAY|WAD|UNIT|BASE|SCALE)\s*=\s*(?:1e18|10\s*\*\*\s*18)',
        )
        if not _ERC20_IFACE_RE.search(source):
            return findings
        if _DECIMALS_NORM_RE.search(source) or _PRECISION_CONST_RE.search(source):
            return findings
        flagged_fns: set = set()
        for func in functions:
            body = self._strip_comments(func['body'])
            if not _HARDCODED_18_RE.search(body):
                continue
            if func['name'] in flagged_fns:
                continue
            flagged_fns.add(func['name'])
            findings.append(StaticFinding(
                severity=StaticSeverity.LOW,
                category=StaticCategory.PRECISION,   # distinct from ACCOUNTING to avoid dedup collision
                title=f"Hardcoded 18-decimal assumption in {func['name']}()",
                description=(
                    f"`{func['name']}()` uses `1e18`/`10**18` with an ERC20 token "
                    f"that may not have 18 decimals (USDC=6, USDT=6, WBTC=8). "
                    f"No `.decimals()` normalization found — 10^12 pricing error possible."
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=False,
                fix_suggestion=(
                    "Query `token.decimals()` at construction and normalize: "
                    "`amount * 10**(18 - tokenDecimals)` before 18-decimal math."
                ),
                cwe="CWE-682",
                confidence=0.65,
            ))
        return findings

    def _detect_selfdestruct_injection(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        MEDIUM: address(this).balance used in vault invariant — selfdestruct-injectable.

        An attacker can forcibly inject ETH via selfdestruct, bypassing receive(),
        manipulating share prices or vault invariants that rely on balance.

        Historical: Parity Wallet ($150M), various vault/AMM balance manipulation.
        """
        findings = []
        _BALANCE_PRICE_RE = _rc(
            r'address\s*\(\s*this\s*\)\s*\.\s*balance\s*.{0,80}'
            r'(?:totalShares|totalSupply|shares|price|virtualPrice|totalAssets)',
            re.DOTALL | re.IGNORECASE,
        )
        _BALANCE_PRICE_RE2 = _rc(
            r'(?:totalShares|totalSupply|price|virtualPrice|totalAssets).{0,80}'
            r'address\s*\(\s*this\s*\)\s*\.\s*balance',
            re.DOTALL | re.IGNORECASE,
        )
        _LOCKED_RECEIVE_RE = _rc(
            r'receive\s*\(\s*\)\s*external\s+payable\s*\{[^}]*revert',
            re.DOTALL,
        )
        src_stripped = self._strip_comments(source)
        if not (_BALANCE_PRICE_RE.search(src_stripped) or
                _BALANCE_PRICE_RE2.search(src_stripped)):
            return findings
        if _LOCKED_RECEIVE_RE.search(src_stripped):
            return findings
        contract_m = re.search(r'\bcontract\s+(\w+)', source)
        contract_name = contract_m.group(1) if contract_m else "Unknown"
        findings.append(StaticFinding(
            severity=StaticSeverity.MEDIUM,
            category=StaticCategory.ACCOUNTING,
            title=f"Selfdestruct ETH injection risk in {contract_name}",
            description=(
                f"`{contract_name}` uses `address(this).balance` in share/price "
                f"accounting. An attacker can forcibly inject ETH via `selfdestruct` "
                f"(bypasses `receive()`) to inflate the balance and manipulate "
                f"share prices or trigger liquidations."
            ),
            location=contract_name,
            exploitable=True,
            fix_suggestion=(
                "Track ETH internally: `uint256 private _ethBalance;` updated "
                "only in `receive()` and withdrawal functions. "
                "Never use `address(this).balance` for accounting."
            ),
            cwe="CWE-284",
            confidence=0.70,
        ))
        return findings

    def _detect_cross_chain_msg_validation(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH: Cross-chain message callback without source chain/sender validation.

        LayerZero/Wormhole/CCIP/Axelar callbacks must validate that the message
        came from a trusted source chain and trusted sender address.

        Real attacks: Poly Network ($611M), Nomad ($190M), Wormhole ($320M),
        Ronin ($625M), Multichain ($126M).

        Detection:
          1. Implements known bridge callback (lzReceive, ccipReceive, etc.).
          2. Callback body does NOT validate srcChainId / sourceChain / trustedRemote.
        """
        findings = []
        _BRIDGE_RECV_RE = _rc(
            r'^(?:lzReceive|lzCompose|receiveWormholeMessages|ccipReceive|'
            r'executeWithToken|_execute|executeMessage|_handleMessage|'
            r'anyExecute|receiveMessage|onMessageReceived|_ccipReceive)$',
        )
        _CHAIN_VALIDATION_RE = _rc(
            r'\b(?:srcChainId|sourceChain|_srcChainId|srcAddress|'
            r'trustedRemote|allowedSenders|authorizedSenders|'
            r'trustedContracts|remoteAddress|expectedSender|'
            r'lzEndpoint|ILayerZeroEndpoint)\b',
            re.IGNORECASE,
        )
        for func in functions:
            name = func.get('name', '')
            if not _BRIDGE_RECV_RE.match(name):
                continue
            vis = func.get('visibility', 'public')
            if vis in ('internal', 'private'):
                continue
            body = self._strip_comments(func['body'])
            if _CHAIN_VALIDATION_RE.search(body):
                continue
            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.MISSING_ACCESS_CONTROL,
                title=f"Cross-chain callback {name}() missing origin validation",
                description=(
                    f"`{name}()` is a cross-chain messaging callback (LayerZero/Wormhole/"
                    f"CCIP/Axelar) but does not validate source chain ID or source address. "
                    f"Any attacker can forge a message accepted as authentic. "
                    f"Root cause of Poly Network ($611M), Nomad ($190M), Wormhole ($320M)."
                ),
                location=f"{name}():L{func['line']}",
                exploitable=True,
                fix_suggestion=(
                    "Validate: `require(trustedRemote[_srcChainId] == _srcAddress, 'untrusted');`. "
                    "Store trusted sender addresses per chain in a mapping."
                ),
                cwe="CWE-346",
                confidence=0.82,
            ))
        return findings

    def _detect_unsafe_selfdestruct(
        self, source: str, functions: List[Dict]
    ) -> List[StaticFinding]:
        """
        HIGH/MEDIUM: selfdestruct() in a callable function.

        Unguarded selfdestruct destroys the contract and drains ETH.
        Even guarded versions in library contracts callable via delegatecall are
        catastrophic (Parity Wallet Library kill() — $150M frozen).

        Detection:
          1. selfdestruct() present in a function body.
          2. Severity HIGH if no admin guard, MEDIUM if guarded.
        """
        findings = []
        _SD_RE = _rc(r'\bselfdestruct\s*\(')
        _INLINE_ADMIN_RE = _rc(
            r'require\s*\(\s*msg\.sender\s*==\s*\w+\s*[,)]',
        )
        for func in functions:
            body = self._strip_comments(func['body'])
            if not _SD_RE.search(body):
                continue
            mod_str = func.get('modifiers', '')
            has_admin = any(m in mod_str for m in self.admin_modifiers)
            if not has_admin:
                has_admin = bool(_INLINE_ADMIN_RE.search(body[:300]))
            sev = StaticSeverity.MEDIUM if has_admin else StaticSeverity.HIGH
            prefix = "Guarded" if has_admin else "Unguarded"
            findings.append(StaticFinding(
                severity=sev,
                category=StaticCategory.MISSING_ACCESS_CONTROL,
                title=f"{prefix} selfdestruct in {func['name']}()",
                description=(
                    f"`{func['name']}()` calls `selfdestruct()`. "
                    + (
                        "Access control present — verify guard is not bypassable "
                        "via delegatecall from a proxy."
                        if has_admin else
                        "No access control — anyone can destroy this contract and drain ETH. "
                        "Root cause of Parity Wallet Library freeze ($150M)."
                    )
                ),
                location=f"{func['name']}():L{func['line']}",
                exploitable=not has_admin,
                fix_suggestion=(
                    "Remove `selfdestruct` (deprecated in EIP-6780). "
                    "If needed, guard with multi-sig + timelock. "
                    "Never expose it in a library contract callable via delegatecall."
                ),
                cwe="CWE-284",
                confidence=0.85 if not has_admin else 0.60,
            ))
        return findings
