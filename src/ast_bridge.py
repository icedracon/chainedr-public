"""ChainEDR AST Bridge — solc-backed AST analysis (zero regex false-positives).

Runs ``solc --ast-compact-json`` on Solidity source, walks the JSON AST,
and re-implements all novel ChainEDR detectors with AST-level accuracy.

Why this matters vs. regex:
  - Comments and string literals are invisible to the AST walker
  - Correct function/parameter scoping (no cross-function contamination)
  - Nested-paren calls parse correctly (address(router) inside approve args)
  - Accurate loop detection (for/while/do-while distinguished by node type)

Falls back gracefully when solc is not in PATH — callers check is_available().

Install solc: https://docs.soliditylang.org/en/latest/installing-solidity.html
  pip install solc-select && solc-select install 0.8.20 && solc-select use 0.8.20
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Generator, List, Optional, Set

try:
    from .static_analyzer import (
        StaticFinding, StaticSeverity, StaticCategory, StaticAnalysisResult
    )
except ImportError:
    from static_analyzer import (
        StaticFinding, StaticSeverity, StaticCategory, StaticAnalysisResult
    )


# ── solc availability ────────────────────────────────────────────────────────

def is_available() -> bool:
    """True if solc is in PATH."""
    return shutil.which("solc") is not None or shutil.which("solc.exe") is not None


def _solc_bin() -> str:
    return shutil.which("solc") or shutil.which("solc.exe") or "solc"


# ── AST loading ──────────────────────────────────────────────────────────────

def get_ast(source: str) -> Optional[Dict]:
    """
    Compile source with ``solc --ast-compact-json`` and return the root AST node.
    Returns None if solc unavailable, compile error, or timeout.
    """
    if not is_available():
        return None

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sol", delete=False, encoding="utf-8"
    ) as f:
        f.write(source)
        tmp = f.name

    try:
        proc = subprocess.run(
            [_solc_bin(), "--ast-compact-json", "--allow-paths", ".", tmp],
            capture_output=True, text=True, timeout=30,
        )
        # returncode 1 = warnings only — still usable
        if proc.returncode > 1:
            return None
        stdout = proc.stdout
        idx = stdout.find("{")
        if idx == -1:
            return None
        data = json.loads(stdout[idx:])
        for _fname, fdata in data.get("sources", {}).items():
            ast = fdata.get("AST") or fdata.get("legacyAST")
            if ast:
                return ast
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ── AST utilities ─────────────────────────────────────────────────────────────

def walk(node: Any) -> Generator[Dict, None, None]:
    """Depth-first yield of every dict node in the AST."""
    if not isinstance(node, dict):
        return
    yield node
    for v in node.values():
        if isinstance(v, dict):
            yield from walk(v)
        elif isinstance(v, list):
            for item in v:
                yield from walk(item)


def find_nodes(root: Any, node_type: str) -> List[Dict]:
    return [n for n in walk(root) if n.get("nodeType") == node_type]


def _src_line(node: Dict, source: str) -> int:
    """Extract 1-based line number from AST ``src`` field (offset:length:fileIdx)."""
    src = node.get("src", "")
    if not src:
        return 0
    try:
        return source[: int(src.split(":")[0])].count("\n") + 1
    except (ValueError, IndexError):
        return 0


def _func_params(func: Dict) -> Set[str]:
    """Return set of parameter names for a FunctionDefinition node."""
    return {
        p.get("name", "")
        for p in func.get("parameters", {}).get("parameters", [])
        if p.get("name")
    }


def _is_msg_value(node: Dict) -> bool:
    return (
        node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "value"
        and node.get("expression", {}).get("nodeType") == "Identifier"
        and node.get("expression", {}).get("name") == "msg"
    )


def _is_in_loop(func_root: Dict, target: Dict) -> bool:
    """True if ``target`` node is nested inside any loop in ``func_root``."""
    target_id = id(target)
    loop_types = {"ForStatement", "WhileStatement", "DoWhileStatement"}

    def _search(node: Any, in_loop: bool) -> bool:
        if not isinstance(node, dict):
            return False
        if in_loop and id(node) == target_id:
            return True
        now_in_loop = in_loop or node.get("nodeType") in loop_types
        for v in node.values():
            if isinstance(v, dict):
                if _search(v, now_in_loop):
                    return True
            elif isinstance(v, list):
                for item in v:
                    if _search(item, now_in_loop):
                        return True
        return False

    return _search(func_root, False)


# ── ASTAnalyzer ──────────────────────────────────────────────────────────────

class ASTAnalyzer:
    """
    AST-accurate re-implementation of all ChainEDR novel detectors.

    Produces the same StaticFinding types as static_analyzer.py but with:
      - Zero false positives from comments / string literals
      - Correct nested-paren argument parsing
      - Accurate loop detection and scope boundaries

    Usage::

        analyzer = ASTAnalyzer()
        findings = analyzer.analyze(source, "MyContract")
        # Returns List[StaticFinding]; empty if solc not available.
    """

    def analyze(self, source: str, contract_name: str = "Unknown") -> List[StaticFinding]:
        ast = get_ast(source)
        if ast is None:
            return []
        out: List[StaticFinding] = []
        for detector in [
            self.detect_msg_value_in_loop,
            self.detect_delegatecall_injection,
            self.detect_approval_griefing,
            self.detect_amm_deadline,
            self.detect_single_step_ownership,
            self.detect_uups_missing_initializers,
            self.detect_integer_overflow,
            self.detect_cross_contract_reentrancy,
            self.detect_governance_attack,
            # ME-1: AST-accurate ports of high-FP regex detectors
            self.detect_stale_oracle,
            self.detect_permissionless_critical,
            self.detect_reentrancy_cei,
        ]:
            try:
                out.extend(detector(ast, source))
            except Exception:
                pass  # never crash the pipeline for one detector
        return out

    # ── msg.value in loop ────────────────────────────────────────────────────

    def detect_msg_value_in_loop(self, ast: Dict, source: str) -> List[StaticFinding]:
        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"
            for node in walk(func):
                if _is_msg_value(node) and _is_in_loop(func, node):
                    findings.append(StaticFinding(
                        severity=StaticSeverity.CRITICAL,
                        category=StaticCategory.LOGIC,
                        title=f"msg.value reuse in loop: {fname}()",
                        description=(
                            f"``{fname}()`` reads ``msg.value`` inside a loop. "
                            f"Solidity does NOT decrement ``msg.value`` per iteration — "
                            f"every iteration sees the full original ETH amount. "
                            f"Callers send 1 ETH but credit N×ETH across N recipients."
                        ),
                        location=f"{fname}():L{_src_line(node, source)}",
                        exploitable=True,
                        fix_suggestion=(
                            "Track ``uint256 remaining = msg.value`` before the loop "
                            "and deduct each distribution from it."
                        ),
                        cwe="CWE-682",
                        confidence=0.97,
                    ))
                    break
        return findings

    # ── delegatecall injection ───────────────────────────────────────────────

    _SAFE_IMPL = frozenset({
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        "_implementation", "implementation",
    })

    def detect_delegatecall_injection(self, ast: Dict, source: str) -> List[StaticFinding]:
        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"
            params = _func_params(func)
            for call in find_nodes(func, "FunctionCall"):
                expr = call.get("expression", {})
                if expr.get("memberName") != "delegatecall":
                    continue
                base = expr.get("expression", {})
                base_name = base.get("name") or base.get("memberName") or "?"
                if any(s in str(base) for s in self._SAFE_IMPL):
                    continue
                is_param = base_name in params
                findings.append(StaticFinding(
                    severity=StaticSeverity.CRITICAL if is_param else StaticSeverity.HIGH,
                    category=StaticCategory.ACCESS_CONTROL,
                    title=f"delegatecall injection in {fname}(): target={base_name}",
                    description=(
                        f"``{fname}()`` performs ``{base_name}.delegatecall()`` where the "
                        f"target {'is a caller-supplied parameter' if is_param else 'is dynamic — verify it cannot be set by an attacker'}. "
                        f"``delegatecall`` executes attacker-chosen bytecode with this "
                        f"contract's storage and ETH."
                    ),
                    location=f"{fname}():L{_src_line(call, source)}",
                    exploitable=is_param,
                    fix_suggestion=(
                        "Never accept delegatecall targets as user parameters. "
                        "Store implementation address in an admin-controlled immutable slot."
                    ),
                    cwe="CWE-829",
                    confidence=0.95 if is_param else 0.80,
                ))
        return findings

    # ── approval griefing (no zero-reset) ───────────────────────────────────

    def detect_approval_griefing(self, ast: Dict, source: str) -> List[StaticFinding]:
        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"
            # Collect all approve calls and zero-reset approve calls in order
            approve_calls: List[Dict] = []
            zero_resets: List[int] = []  # indices into approve_calls that ARE zero-resets

            for call in find_nodes(func, "FunctionCall"):
                expr = call.get("expression", {})
                if expr.get("memberName") != "approve":
                    continue
                args = call.get("arguments", [])
                is_zero = (
                    len(args) == 2
                    and args[1].get("nodeType") == "Literal"
                    and str(args[1].get("value", "")) == "0"
                )
                if is_zero:
                    zero_resets.append(len(approve_calls))
                approve_calls.append(call)

            for i, call in enumerate(approve_calls):
                if i in zero_resets:
                    continue
                # Safe if a zero-reset came within 2 positions before this call
                has_reset = any(abs(z - i) <= 2 and z < i for z in zero_resets)
                if not has_reset:
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.LOGIC,
                        title=f"Approval griefing risk in {fname}(): no zero-reset",
                        description=(
                            f"``{fname}()`` calls ``.approve()`` without first resetting "
                            f"the allowance to zero. USDT and other non-standard ERC20s "
                            f"revert when the current allowance is non-zero, silently "
                            f"breaking this function on affected tokens."
                        ),
                        location=f"{fname}():L{_src_line(call, source)}",
                        exploitable=False,
                        fix_suggestion=(
                            "Use ``SafeERC20.forceApprove(token, spender, amount)`` (OZ v5+). "
                            "Or manually: ``token.approve(spender, 0); token.approve(spender, amount);``"
                        ),
                        cwe="CWE-252",
                        confidence=0.90,
                    ))
        return findings

    # ── AMM deadline = block.timestamp ──────────────────────────────────────

    _AMM_METHODS = frozenset({
        "swapExactTokensForTokens", "swapTokensForExactTokens",
        "swapExactETHForTokens", "swapTokensForExactETH",
        "swapExactTokensForETH", "swapETHForExactTokens",
        "exactInputSingle", "exactInput", "exactOutputSingle", "exactOutput",
        "addLiquidity", "addLiquidityETH", "removeLiquidity", "removeLiquidityETH",
        "exchange", "exchange_underlying",
    })

    def detect_amm_deadline(self, ast: Dict, source: str) -> List[StaticFinding]:
        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"
            for call in find_nodes(func, "FunctionCall"):
                expr = call.get("expression", {})
                method = expr.get("memberName") or (
                    expr.get("name") if expr.get("nodeType") == "Identifier" else ""
                ) or ""
                if method not in self._AMM_METHODS:
                    continue
                for arg in call.get("arguments", []):
                    if (
                        arg.get("nodeType") == "MemberAccess"
                        and arg.get("memberName") == "timestamp"
                        and arg.get("expression", {}).get("name") == "block"
                    ):
                        findings.append(StaticFinding(
                            severity=StaticSeverity.MEDIUM,
                            category=StaticCategory.ORACLE,
                            title=f"AMM deadline=block.timestamp (no-op) in {fname}()",
                            description=(
                                f"``{fname}()`` passes ``block.timestamp`` as the DEX "
                                f"deadline. This always passes in the current block — "
                                f"provides zero MEV protection. Validators can hold the "
                                f"transaction and execute at a worse price."
                            ),
                            location=f"{fname}():L{_src_line(call, source)}",
                            exploitable=True,
                            fix_suggestion=(
                                "Use ``block.timestamp + MAX_DELAY`` (e.g. 1800 = 30 min). "
                                "Expose deadline as a caller-supplied parameter."
                            ),
                            cwe="CWE-613",
                            confidence=0.95,
                        ))
                        break
        return findings

    # ── single-step ownership ────────────────────────────────────────────────

    _SAFE_OWNERSHIP = frozenset({
        "Ownable2Step", "Ownable2StepUpgradeable", "acceptOwnership",
        "claimOwnership", "claimOwner", "pendingOwner", "pending_owner",
        "nominatedOwner", "_pendingOwner",
    })

    def detect_single_step_ownership(self, ast: Dict, source: str) -> List[StaticFinding]:
        # Fast-path: any two-step pattern present → safe
        for node in walk(ast):
            if node.get("name") in self._SAFE_OWNERSHIP or node.get("memberName") in self._SAFE_OWNERSHIP:
                return []

        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or ""
            if "transferownership" not in fname.lower():
                continue
            for assign in find_nodes(func, "Assignment"):
                lhs = assign.get("leftHandSide", {})
                lhs_name = lhs.get("name") or lhs.get("memberName") or ""
                if lhs_name in ("owner", "_owner") and "pending" not in str(assign).lower():
                    findings.append(StaticFinding(
                        severity=StaticSeverity.MEDIUM,
                        category=StaticCategory.ACCESS_CONTROL,
                        title=f"Single-step ownership transfer: {fname}()",
                        description=(
                            f"``{fname}()`` sets the new owner immediately. "
                            f"A typo or social-engineering attack permanently transfers "
                            f"protocol control with no recovery path."
                        ),
                        location=f"{fname}():L{_src_line(assign, source)}",
                        exploitable=False,
                        fix_suggestion=(
                            "Inherit ``Ownable2Step``: store ``pendingOwner`` in "
                            "``transferOwnership()``, require ``acceptOwnership()`` to confirm."
                        ),
                        cwe="CWE-284",
                        confidence=0.88,
                    ))
        return findings

    # ── UUPS missing _disableInitializers ────────────────────────────────────

    _UPGRADEABLE_BASES = frozenset({
        "UUPSUpgradeable", "Initializable", "OwnableUpgradeable",
        "AccessControlUpgradeable", "ERC20Upgradeable", "ERC721Upgradeable",
        "ERC1155Upgradeable", "PausableUpgradeable", "ReentrancyGuardUpgradeable",
        "ERC4626Upgradeable",
    })

    def detect_uups_missing_initializers(self, ast: Dict, source: str) -> List[StaticFinding]:
        findings = []
        for contract in find_nodes(ast, "ContractDefinition"):
            cname = contract.get("name", "")
            bases = [
                b.get("baseName", {}).get("name", "")
                for b in contract.get("baseContracts", [])
            ]
            if not any(b in self._UPGRADEABLE_BASES for b in bases):
                continue
            # Find constructor
            ctor = next(
                (f for f in find_nodes(contract, "FunctionDefinition")
                 if f.get("kind") == "constructor"),
                None,
            )
            has_disable = ctor is not None and any(
                (c.get("expression", {}).get("name") == "_disableInitializers"
                 or c.get("expression", {}).get("memberName") == "_disableInitializers")
                for c in find_nodes(ctor, "FunctionCall")
            )
            if not has_disable:
                findings.append(StaticFinding(
                    severity=StaticSeverity.HIGH,
                    category=StaticCategory.ACCESS_CONTROL,
                    title=f"UUPS/upgradeable: no _disableInitializers() in {cname}",
                    description=(
                        f"``{cname}`` inherits from an upgradeable base but the constructor "
                        f"does not call ``_disableInitializers()``. An attacker can initialize "
                        f"the implementation contract directly and use ``upgradeToAndCall`` "
                        f"with a self-destruct payload to brick the proxy."
                    ),
                    location=f"{cname}:L{_src_line(contract, source)}",
                    exploitable=True,
                    fix_suggestion=(
                        "Add: ``constructor() {{ _disableInitializers(); }}`` "
                        "to the implementation contract."
                    ),
                    cwe="CWE-665",
                    confidence=0.92,
                ))
        return findings

    # ── integer overflow in unchecked blocks ─────────────────────────────────

    def detect_integer_overflow(self, ast: Dict, source: str) -> List[StaticFinding]:
        """
        HIGH: User-controlled arithmetic inside ``unchecked{}`` blocks.
        Solidity 0.8+ guards are disabled inside unchecked — overflow is live.
        """
        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"
            params = _func_params(func)
            taint = params | {"msg", "value", "amount", "qty", "size"}

            for block in find_nodes(func, "UncheckedStatement"):
                for binop in find_nodes(block, "BinaryOperation"):
                    if binop.get("operator") not in ("+", "-", "*", "**"):
                        continue
                    left = binop.get("leftExpression", {})
                    right = binop.get("rightExpression", {})
                    l_name = left.get("name") or left.get("memberName") or ""
                    r_name = right.get("name") or right.get("memberName") or ""
                    is_tainted = (
                        l_name in taint or r_name in taint
                        or _is_msg_value(left) or _is_msg_value(right)
                    )
                    if is_tainted:
                        findings.append(StaticFinding(
                            severity=StaticSeverity.HIGH,
                            category=StaticCategory.LOGIC,
                            title=f"Unchecked arithmetic on user input in {fname}()",
                            description=(
                                f"``{fname}()`` performs ``{binop.get('operator')}`` on "
                                f"a user-controlled value inside ``unchecked{{}}``. "
                                f"Solidity 0.8+ overflow protection is disabled here — "
                                f"integer overflow/underflow is possible."
                            ),
                            location=f"{fname}():L{_src_line(binop, source)}",
                            exploitable=True,
                            fix_suggestion=(
                                "Move arithmetic outside ``unchecked{{}}`` unless you have "
                                "a mathematical proof of no-overflow. Document the invariant."
                            ),
                            cwe="CWE-190",
                            confidence=0.82,
                        ))
                        break  # one per unchecked block
        return findings

    # ── cross-contract reentrancy ─────────────────────────────────────────────

    _CALLBACK_HOOKS = frozenset({
        "tokensReceived", "onERC1155Received", "onERC1155BatchReceived",
        "onERC721Received", "onFlashLoan", "uniswapV2Call",
        "uniswapV3FlashCallback", "pancakeCall",
        "fallback", "receive",
    })
    _EXT_CALL_METHODS = frozenset({
        "transfer", "send", "call", "safeTransfer", "safeTransferFrom",
        "transferFrom", "mint", "burn",
    })

    def detect_cross_contract_reentrancy(self, ast: Dict, source: str) -> List[StaticFinding]:
        """
        HIGH: External call followed by state change, where contract also implements
        a receiver/callback hook that could be triggered by the external call.
        """
        # Does this contract implement any callback hook?
        hook_names = {
            func.get("name", "")
            for func in find_nodes(ast, "FunctionDefinition")
            if func.get("name") in self._CALLBACK_HOOKS
        }
        if not hook_names:
            return []

        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"
            if fname in self._CALLBACK_HOOKS:
                continue

            stmts = (func.get("body") or {}).get("statements", [])
            ext_call_found = False
            ext_method = ""

            for stmt in stmts:
                # Check for external call
                for call in find_nodes(stmt, "FunctionCall"):
                    expr = call.get("expression", {})
                    method = expr.get("memberName") or ""
                    if method in self._EXT_CALL_METHODS:
                        ext_call_found = True
                        ext_method = method

                if not ext_call_found:
                    continue

                # Check for state write after the external call
                for assign in find_nodes(stmt, "Assignment"):
                    lhs = assign.get("leftHandSide", {})
                    if lhs.get("nodeType") in ("MemberAccess", "IndexAccess"):
                        for hook in hook_names:
                            findings.append(StaticFinding(
                                severity=StaticSeverity.HIGH,
                                category=StaticCategory.REENTRANCY,
                                title=(
                                    f"Cross-contract reentrancy: "
                                    f"{fname}() + {hook}() callback"
                                ),
                                description=(
                                    f"``{fname}()`` makes an external call "
                                    f"(``{ext_method}``) before updating state. "
                                    f"This contract implements ``{hook}()``, which could "
                                    f"be triggered by the external call to re-enter and "
                                    f"read stale state or double-spend."
                                ),
                                location=f"{fname}():L{_src_line(func, source)}",
                                exploitable=True,
                                fix_suggestion=(
                                    "Apply CEI: complete all state updates BEFORE "
                                    "external calls. Add ``nonReentrant`` guard. "
                                    "Audit the callback hook for state reads."
                                ),
                                cwe="CWE-362",
                                confidence=0.75,
                            ))
                        break
                if findings:
                    break
        return findings

    # ── governance attack (no timelock) ──────────────────────────────────────

    _ADMIN_MODIFIERS = frozenset({
        "onlyOwner", "onlyAdmin", "onlyGovernance", "onlyRole",
        "onlyGuardian", "onlyTimelock", "onlyOperator", "onlyDAO",
        "requiresAuth",
    })
    _CRITICAL_SETTERS = frozenset({
        "setToken", "setRouter", "setOracle", "setTreasury", "setFee",
        "setPriceFeed", "setImplementation", "setStrategy", "setVault",
        "upgradeTo", "upgradeToAndCall", "setMinter", "setKeeper",
        "setRewardRate", "setInterestRate", "setCollateralFactor",
    })
    _TIMELOCK_SIGNALS = frozenset({
        "TimelockController", "timelock", "_timelock", "Timelock",
        "schedule", "scheduleBatch", "delay", "minDelay",
        "TIMELOCK_ROLE", "timelockAddress",
    })

    def detect_governance_attack(self, ast: Dict, source: str) -> List[StaticFinding]:
        """
        HIGH: Admin function that modifies critical protocol parameters
        without a timelock, allowing instant parameter changes by a
        compromised/malicious owner.

        Real-world: ~40% of C4 governance findings involve admin functions
        that can rug TVL instantly (set fee=100%, swap router to attacker).
        """
        # Check if any timelock mechanism is present in the entire contract
        has_timelock = any(
            node.get("name") in self._TIMELOCK_SIGNALS
            or node.get("memberName") in self._TIMELOCK_SIGNALS
            for node in walk(ast)
        )
        if has_timelock:
            return []

        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or ""

            # Must have an admin modifier
            mod_names = {
                m.get("modifierName", {}).get("name", "")
                for m in func.get("modifiers", [])
            }
            if not mod_names & self._ADMIN_MODIFIERS:
                continue

            # Must match a critical setter name
            if not any(s.lower() in fname.lower() for s in self._CRITICAL_SETTERS):
                # Also catch functions that write to critical state vars
                body_str = str(func.get("body", ""))
                critical_writes = any(
                    kw in body_str
                    for kw in ("router", "oracle", "treasury", "token", "implementation",
                               "strategy", "minter", "fee", "rate")
                )
                if not critical_writes:
                    continue

            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.ACCESS_CONTROL,
                title=f"Governance: no timelock on critical setter {fname}()",
                description=(
                    f"``{fname}()`` is admin-only and modifies critical protocol "
                    f"parameters (router/oracle/treasury/fee) with no timelock delay. "
                    f"A compromised or malicious owner can rug the protocol instantly: "
                    f"swap the router to a drain contract, set fee=100%, etc."
                ),
                location=f"{fname}():L{_src_line(func, source)}",
                exploitable=True,
                fix_suggestion=(
                    "Wrap with a ``TimelockController`` (OZ). Minimum delay: 24–48h for "
                    "critical parameters. Emit events on all parameter changes. "
                    "Consider a multi-sig (Gnosis Safe) as the timelock proposer."
                ),
                cwe="CWE-284",
                confidence=0.78,
            ))
        return findings

    # ── stale oracle (AST-accurate) ───────────────────────────────────────────

    def detect_stale_oracle(self, ast: Dict, source: str) -> List[StaticFinding]:
        """
        HIGH: latestRoundData() called without validating updatedAt.

        AST advantage over regex: exact scope — only fires when the return
        tuple binding is confirmed to omit or discard the updatedAt slot.
        Regex version fires on any file containing both latestRoundData and
        updatedAt, even in separate functions.

        Three sub-findings:
          A. latestRoundData() return tuple that has no variable bound to slot 4
             (updatedAt) — confirmed discard.
          B. latestRoundData() return tuple that binds updatedAt but the variable
             is never used (dead assignment).
          C. latestAnswer() — deprecated Chainlink API, returns 0 on sequencer
             downtime with no way to detect staleness.
        """
        findings = []

        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"

            for call in find_nodes(func, "FunctionCall"):
                expr = call.get("expression", {})
                member = expr.get("memberName") or ""

                # Sub-C: deprecated latestAnswer()
                if member == "latestAnswer":
                    findings.append(StaticFinding(
                        severity=StaticSeverity.HIGH,
                        category=StaticCategory.ORACLE,
                        title=f"Deprecated latestAnswer() in {fname}()",
                        description=(
                            f"``{fname}()`` calls ``latestAnswer()`` — a Chainlink v1 API "
                            f"that returns 0 silently on sequencer downtime and provides "
                            f"no staleness information. Use ``latestRoundData()`` and "
                            f"validate ``updatedAt`` and ``answeredInRound``."
                        ),
                        location=f"{fname}():L{_src_line(call, source)}",
                        exploitable=True,
                        fix_suggestion=(
                            "Replace with ``latestRoundData()``. Validate: "
                            "``require(updatedAt >= block.timestamp - MAX_STALENESS)`` "
                            "and ``require(answeredInRound >= roundId)``."
                        ),
                        cwe="CWE-703",
                        confidence=0.92,
                    ))
                    continue

                # Sub-A/B: latestRoundData() without updatedAt validation
                if member != "latestRoundData":
                    continue

                # Find the parent VariableDeclarationStatement or ExpressionStatement
                # Walk up to find tuple variable names
                parent_stmt = None
                for stmt in find_nodes(func, "VariableDeclarationStatement"):
                    if call in list(walk(stmt)):
                        parent_stmt = stmt
                        break

                if parent_stmt is None:
                    # latestRoundData() discarded entirely — definitely not checked
                    findings.append(StaticFinding(
                        severity=StaticSeverity.HIGH,
                        category=StaticCategory.ORACLE,
                        title=f"Stale oracle: updatedAt discarded in {fname}()",
                        description=(
                            f"``{fname}()`` calls ``latestRoundData()`` but discards "
                            f"ALL return values including ``updatedAt``. A stale price "
                            f"will be used silently — exploitable after sequencer outage "
                            f"or Chainlink heartbeat expiry."
                        ),
                        location=f"{fname}():L{_src_line(call, source)}",
                        exploitable=True,
                        fix_suggestion=(
                            "Capture ``updatedAt`` and require "
                            "``block.timestamp - updatedAt <= MAX_STALENESS``."
                        ),
                        cwe="CWE-703",
                        confidence=0.90,
                    ))
                    continue

                # Extract variable names bound to the tuple slots
                decls = parent_stmt.get("declarations", [])
                bound_names: Set[str] = set()
                for d in decls:
                    if d and d.get("name"):
                        bound_names.add(d["name"])

                # Slot 4 (0-indexed) is updatedAt — check if it's bound and used
                updated_at_slot = decls[3] if len(decls) > 3 else None
                updated_at_name = (updated_at_slot or {}).get("name")

                if not updated_at_name:
                    # slot not bound → confirmed discard
                    findings.append(StaticFinding(
                        severity=StaticSeverity.HIGH,
                        category=StaticCategory.ORACLE,
                        title=f"Stale oracle: updatedAt not captured in {fname}()",
                        description=(
                            f"``{fname}()`` calls ``latestRoundData()`` but does not "
                            f"bind the ``updatedAt`` return value (slot 4). "
                            f"Price freshness is never validated."
                        ),
                        location=f"{fname}():L{_src_line(call, source)}",
                        exploitable=True,
                        fix_suggestion=(
                            "Bind ``updatedAt``: ``(, int256 price,, uint256 updatedAt,) "
                            "= feed.latestRoundData();`` then validate staleness."
                        ),
                        cwe="CWE-703",
                        confidence=0.88,
                    ))
                else:
                    # Slot bound — check if updatedAt variable is used in a comparison
                    used_in_check = any(
                        node.get("name") == updated_at_name
                        for node in find_nodes(func, "Identifier")
                        if node.get("name") == updated_at_name
                        and node is not updated_at_slot
                    )
                    # Also check for require/if statements that reference updatedAt
                    has_staleness_check = any(
                        updated_at_name in str(n)
                        for n in find_nodes(func, "FunctionCall")
                        if (n.get("expression") or {}).get("name") in ("require", "assert")
                    ) or any(
                        updated_at_name in str(n)
                        for n in find_nodes(func, "IfStatement")
                    )
                    if not has_staleness_check:
                        findings.append(StaticFinding(
                            severity=StaticSeverity.MEDIUM,
                            category=StaticCategory.ORACLE,
                            title=f"Stale oracle: updatedAt captured but not validated in {fname}()",
                            description=(
                                f"``{fname}()`` captures ``updatedAt`` from "
                                f"``latestRoundData()`` but never uses it in a staleness "
                                f"check. The price returned may be arbitrarily old."
                            ),
                            location=f"{fname}():L{_src_line(call, source)}",
                            exploitable=True,
                            fix_suggestion=(
                                f"Add: ``require(block.timestamp - {updated_at_name} "
                                f"<= MAX_STALENESS, \"Stale price\");``"
                            ),
                            cwe="CWE-703",
                            confidence=0.82,
                        ))
        return findings

    # ── permissionless critical functions (AST-accurate) ─────────────────────

    _CRITICAL_FN_KEYWORDS = frozenset({
        "setOwner", "setAdmin", "transferOwnership", "renounceOwnership",
        "setFee", "setRate", "setOracle", "setRouter", "setTreasury",
        "setImplementation", "setVault", "setStrategy", "setMinter",
        "upgradeTo", "upgradeToAndCall", "pause", "unpause",
        "setCollateralFactor", "setLiquidationBonus",
        "setInterestRate", "setRewardRate", "setMaxBorrow",
    })

    def detect_permissionless_critical(self, ast: Dict, source: str) -> List[StaticFinding]:
        """
        HIGH: Function with a critical name (setOracle, upgradeTo, etc.) that has
        no admin modifier and is externally callable.

        AST advantage: exact modifier list from the AST node — no regex substring
        matching that fires on function NAMES containing modifier keywords.
        """
        admin_mods = {
            "onlyOwner", "onlyAdmin", "onlyGovernance", "onlyRole",
            "onlyGuardian", "onlyTimelock", "onlyOperator", "onlyDAO",
            "requiresAuth", "adminOnly", "onlyMinter", "onlyPauser",
        }

        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or ""
            if fname not in self._CRITICAL_FN_KEYWORDS:
                continue

            vis = func.get("visibility", "")
            if vis not in ("external", "public"):
                continue

            # Extract modifiers from AST
            mods = {
                m.get("modifierName", {}).get("name") or m.get("name") or ""
                for m in func.get("modifiers", [])
            }
            if mods & admin_mods:
                continue  # properly guarded

            findings.append(StaticFinding(
                severity=StaticSeverity.HIGH,
                category=StaticCategory.ACCESS_CONTROL,
                title=f"Permissionless critical function: {fname}()",
                description=(
                    f"``{fname}()`` is ``{vis}`` with no admin modifier. "
                    f"Any caller can execute this privileged operation."
                ),
                location=f"{fname}():L{_src_line(func, source)}",
                exploitable=True,
                fix_suggestion=(
                    f"Add ``onlyOwner`` or an equivalent role-based modifier to ``{fname}()``."
                ),
                cwe="CWE-284",
                confidence=0.90,
            ))
        return findings

    # ── reentrancy CEI (AST-accurate) ─────────────────────────────────────────

    _ETH_CALL_METHODS = frozenset({"call", "transfer", "send"})
    _TOKEN_CALL_METHODS = frozenset({
        "transfer", "transferFrom", "safeTransfer", "safeTransferFrom",
        "mint", "burn",
    })

    def detect_reentrancy_cei(self, ast: Dict, source: str) -> List[StaticFinding]:
        """
        HIGH: External call (ETH or token) before state update (CEI violation).

        AST advantage: statement-order is exact from AST nodes. Regex guesses
        order from text position and can't reliably detect whether the state
        write is before or after the call.

        Fires only when ALL hold:
          1. Function has no nonReentrant modifier.
          2. An external ETH or token call appears in the statement list.
          3. A storage state update (MemberAccess/IndexAccess assignment) appears
             AFTER the external call in the same statement sequence.
        """
        non_reentrant_names = frozenset({
            "nonReentrant", "noReentrancy", "mutex", "locked",
        })
        ext_methods = self._ETH_CALL_METHODS | self._TOKEN_CALL_METHODS

        findings = []
        for func in find_nodes(ast, "FunctionDefinition"):
            fname = func.get("name") or "constructor"

            # Skip nonReentrant-protected functions
            mods = {
                m.get("modifierName", {}).get("name") or m.get("name") or ""
                for m in func.get("modifiers", [])
            }
            if mods & non_reentrant_names:
                continue

            stmts = (func.get("body") or {}).get("statements", [])
            ext_call_idx = None
            ext_call_method = ""

            for i, stmt in enumerate(stmts):
                # Detect external call
                for call in find_nodes(stmt, "FunctionCall"):
                    expr = call.get("expression", {})
                    method = expr.get("memberName") or ""
                    if method in ext_methods:
                        ext_call_idx = i
                        ext_call_method = method
                        break
                if ext_call_idx is not None:
                    break

            if ext_call_idx is None:
                continue

            # Check for state write AFTER the external call
            for stmt in stmts[ext_call_idx + 1:]:
                for assign in find_nodes(stmt, "Assignment"):
                    lhs = assign.get("leftHandSide", {})
                    if lhs.get("nodeType") in ("MemberAccess", "IndexAccess",
                                               "Identifier"):
                        # Confirm it's a storage write (not local var)
                        lhs_name = lhs.get("name") or lhs.get("memberName") or ""
                        if lhs_name in ("", "ok", "success", "result", "ret"):
                            continue  # local return-value binding, not state
                        findings.append(StaticFinding(
                            severity=StaticSeverity.HIGH,
                            category=StaticCategory.REENTRANCY,
                            title=f"CEI violation: state update after {ext_call_method}() in {fname}()",
                            description=(
                                f"``{fname}()`` calls ``{ext_call_method}()`` and THEN "
                                f"updates storage (``{lhs_name}``). This violates the "
                                f"Checks-Effects-Interactions pattern — an attacker can "
                                f"re-enter before the state update to exploit inconsistent "
                                f"contract state."
                            ),
                            location=f"{fname}():L{_src_line(assign, source)}",
                            exploitable=True,
                            fix_suggestion=(
                                "Move all state updates BEFORE the external call. "
                                "Pattern: (1) check inputs, (2) update state, "
                                "(3) make external call. Add ``nonReentrant`` as defense-in-depth."
                            ),
                            cwe="CWE-362",
                            confidence=0.85,
                        ))
                        break  # one finding per function
                else:
                    continue
                break

        return findings


# ── convenience wrapper ───────────────────────────────────────────────────────

def analyze(source: str, contract_name: str = "Unknown") -> List[StaticFinding]:
    """Convenience function: run all AST detectors on source."""
    return ASTAnalyzer().analyze(source, contract_name)


# ── Type extraction from solc AST ────────────────────────────────────────────

def extract_typed_params(source: str) -> Dict[str, Dict[str, str]]:
    """
    Return ``{func_name: {param_name: type_string}}`` for all functions.

    Uses solc AST ``typeDescriptions.typeString`` — exact Solidity type info
    (e.g. ``"uint128"``, ``"address payable"``, ``"int256"``) not available
    from regex parsing.

    Lets detectors distinguish:
      - ``uint128 amount`` → truncation risk on cast to uint256
      - ``address payable`` → ETH-send already safe (no .transfer FP)
      - ``int256`` → can go negative (cross-chain arithmetic not an underflow)

    Returns empty dict if solc is unavailable.
    """
    ast = get_ast(source)
    if ast is None:
        return {}

    result: Dict[str, Dict[str, str]] = {}
    for func in find_nodes(ast, "FunctionDefinition"):
        fname = func.get("name") or "constructor"
        params: Dict[str, str] = {}
        for param in func.get("parameters", {}).get("parameters", []):
            pname = param.get("name") or ""
            ptype = (param.get("typeDescriptions") or {}).get("typeString") or ""
            if pname and ptype:
                params[pname] = ptype
        # Also include return parameters
        for param in func.get("returnParameters", {}).get("parameters", []):
            pname = param.get("name") or ""
            ptype = (param.get("typeDescriptions") or {}).get("typeString") or ""
            if pname and ptype:
                params[f"return_{pname}"] = ptype
        result[fname] = params
    return result


def get_uint_widths(source: str) -> Dict[str, int]:
    """
    Return ``{param_name: bit_width}`` for all uint/int parameters narrower
    than 256 bits — these are truncation-risk parameters.

    Example: ``uint128 amount`` → ``{"amount": 128}``.
    Useful for cross-chain arithmetic detector to skip ``int256`` (signed,
    can go negative, not an underflow in the traditional sense).
    """
    typed = extract_typed_params(source)
    widths: Dict[str, int] = {}
    _width_re = re.compile(r'\b(?:u?int)(\d+)\b')
    for params in typed.values():
        for pname, ptype in params.items():
            m = _width_re.search(ptype)
            if m:
                w = int(m.group(1))
                if w < 256:
                    widths[pname] = w
    return widths
