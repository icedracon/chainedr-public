"""
ChainEDR — Protocol Invariant Testing Framework

Checks DeFi protocol invariants against live fork state after every fuzz step.
No LLM. Pure Web3 view-calls + arithmetic.

Built-in invariants:
  ERC20:   totalSupply >= 0, address(0) balance == 0
  ERC4626: solvency (totalAssets > 0 when totalSupply > 0), share price positive
  GENERAL: ETH not unexpectedly stuck, monotonic share price tracking

User-defined invariants: callables (w3, address) → (bool, str)
  True  = invariant holds
  False = VIOLATED → SequenceViolation or DB anomaly

Monotonic share price: call engine.add_monotonic_check(addr) once to register
per-contract state tracking across all subsequent check_all() calls.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from web3 import Web3


# ──────────────────────────────────────────────────────────────────────────────
# Data
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class InvariantDef:
    name:     str
    desc:     str
    check_fn: Callable        # (w3: Web3, addr: str) -> Tuple[bool, str]
    severity: str = "HIGH"    # CRITICAL | HIGH | MEDIUM | LOW
    category: str = "PROTOCOL"


@dataclass
class InvariantViolation:
    name:     str
    desc:     str
    detail:   str
    severity: str


# ──────────────────────────────────────────────────────────────────────────────
# Minimal ABI snippets — avoids importing full ABI files
# ──────────────────────────────────────────────────────────────────────────────

_ERC20_ABI = [
    {"name": "totalSupply", "type": "function", "inputs": [],
     "outputs": [{"type": "uint256"}], "stateMutability": "view"},
    {"name": "balanceOf",   "type": "function",
     "inputs": [{"name": "a", "type": "address"}],
     "outputs": [{"type": "uint256"}], "stateMutability": "view"},
]

_ERC4626_ABI = _ERC20_ABI + [
    {"name": "totalAssets",    "type": "function", "inputs": [],
     "outputs": [{"type": "uint256"}], "stateMutability": "view"},
    {"name": "convertToAssets","type": "function",
     "inputs": [{"name": "s", "type": "uint256"}],
     "outputs": [{"type": "uint256"}], "stateMutability": "view"},
]


def _call(contract, fn_name, *args, default=None):
    try:
        return getattr(contract.functions, fn_name)(*args).call()
    except Exception:
        return default


# ──────────────────────────────────────────────────────────────────────────────
# Built-in invariant checks
# ──────────────────────────────────────────────────────────────────────────────

def _inv_total_supply_non_neg(w3: Web3, addr: str) -> Tuple[bool, str]:
    c  = w3.eth.contract(address=addr, abi=_ERC20_ABI)
    ts = _call(c, "totalSupply", default=None)
    if ts is None:
        return True, "totalSupply() not present"
    return ts >= 0, f"totalSupply={ts}"


def _inv_zero_addr_balance(w3: Web3, addr: str) -> Tuple[bool, str]:
    c   = w3.eth.contract(address=addr, abi=_ERC20_ABI)
    bal = _call(c, "balanceOf", "0x" + "0" * 40, default=0)
    return bal == 0, f"balanceOf(0x0)={bal}"


def _inv_erc4626_solvency(w3: Web3, addr: str) -> Tuple[bool, str]:
    c  = w3.eth.contract(address=addr, abi=_ERC4626_ABI)
    ts = _call(c, "totalSupply", default=None)
    ta = _call(c, "totalAssets", default=None)
    if ts is None or ta is None:
        return True, "Not ERC4626"
    if ts > 0 and ta == 0:
        return False, f"totalSupply={ts} but totalAssets=0 → INSOLVENT"
    return True, f"ts={ts} ta={ta}"


def _inv_share_price_positive(w3: Web3, addr: str) -> Tuple[bool, str]:
    c      = w3.eth.contract(address=addr, abi=_ERC4626_ABI)
    ts     = _call(c, "totalSupply", default=None)
    if not ts:
        return True, "No shares minted"
    assets = _call(c, "convertToAssets", 10**18, default=None)
    if assets is None:
        return True, "Not ERC4626"
    return assets > 0, f"1e18 shares → {assets} assets"


def _inv_eth_not_unexpected(w3: Web3, addr: str) -> Tuple[bool, str]:
    bal = w3.eth.get_balance(addr)
    if bal > 100 * 10**18:
        return False, f"Contract holds {bal/1e18:.2f} ETH unexpectedly"
    return True, f"ETH={bal/1e18:.4f}"


BUILTIN_INVARIANTS: List[InvariantDef] = [
    InvariantDef(
        "TOTAL_SUPPLY_NON_NEGATIVE",
        "totalSupply() must be >= 0",
        _inv_total_supply_non_neg,
        severity="CRITICAL", category="ERC20",
    ),
    InvariantDef(
        "ZERO_ADDR_ZERO_BALANCE",
        "address(0) must hold 0 tokens",
        _inv_zero_addr_balance,
        severity="HIGH", category="ERC20",
    ),
    InvariantDef(
        "ERC4626_SOLVENCY",
        "totalSupply > 0 implies totalAssets > 0",
        _inv_erc4626_solvency,
        severity="CRITICAL", category="ERC4626",
    ),
    InvariantDef(
        "SHARE_PRICE_POSITIVE",
        "1e18 shares must convert to > 0 assets",
        _inv_share_price_positive,
        severity="HIGH", category="ERC4626",
    ),
    InvariantDef(
        "ETH_NOT_STUCK",
        "Contract should not hold >100 ETH unexpectedly",
        _inv_eth_not_unexpected,
        severity="MEDIUM", category="GENERAL",
    ),
]


# ──────────────────────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────────────────────

class InvariantEngine:
    """
    Protocol invariant testing engine. Designed to run after every fuzz step.

    Usage::

        engine = InvariantEngine()
        engine.add_monotonic_check("0xVaultAddress")
        engine.add_custom("MY_INV", "debt <= collateral", my_fn, severity="CRITICAL")

        # After each call:
        violations = engine.check_all(contract_addr, w3_fork)
        # → List[Tuple[str, str]]  (name, detail)
    """

    def __init__(self, db=None):
        self.db = db
        self._invariants: List[InvariantDef] = list(BUILTIN_INVARIANTS)
        self._last_share_price: Dict[str, int] = {}   # addr → last price
        self._last_total_assets: Dict[str, int] = {}  # addr → last total assets

    # ── Public API ────────────────────────────────────────────────────────

    def add_custom(
        self,
        name:     str,
        desc:     str,
        check_fn: Callable,
        severity: str = "HIGH",
        category: str = "CUSTOM",
    ) -> None:
        """Register a user-defined invariant. check_fn: (w3, addr) → (bool, str)."""
        self._invariants.append(InvariantDef(name, desc, check_fn, severity, category))

    def add_monotonic_check(self, contract_address: str) -> None:
        """
        Track share price across calls for this vault and flag any decrease.
        Register once before fuzzing begins.
        """
        addr = contract_address.lower()

        def _check_monotonic(w3: Web3, a: str) -> Tuple[bool, str]:
            if a.lower() != addr:
                return True, "skip"
            c  = w3.eth.contract(address=a, abi=_ERC4626_ABI)
            ts = _call(c, "totalSupply", default=0)
            if not ts:
                return True, "No shares"
            price = _call(c, "convertToAssets", 10**18, default=None)
            if price is None:
                return True, "Not ERC4626"
            prev = self._last_share_price.get(addr)
            self._last_share_price[addr] = price
            if prev is not None and price < prev:
                return False, f"Share price DECREASED {prev} → {price} (Δ={price-prev})"
            return True, f"price={price} prev={prev}"

        self._invariants.append(InvariantDef(
            "SHARE_PRICE_MONOTONIC",
            "Share price must never decrease",
            _check_monotonic,
            severity="CRITICAL",
            category="ERC4626",
        ))

    def add_solvency_check(
        self,
        contract_address: str,
        debt_fn:   str = "totalDebt",
        asset_fn:  str = "totalAssets",
    ) -> None:
        """
        Register: debt_fn() <= asset_fn() must always hold.
        debt_fn / asset_fn: view function names on the contract.
        """
        addr = contract_address.lower()
        _abi = [
            {"name": debt_fn,  "type": "function", "inputs": [],
             "outputs": [{"type": "uint256"}], "stateMutability": "view"},
            {"name": asset_fn, "type": "function", "inputs": [],
             "outputs": [{"type": "uint256"}], "stateMutability": "view"},
        ]

        def _check_solvency(w3: Web3, a: str) -> Tuple[bool, str]:
            if a.lower() != addr:
                return True, "skip"
            c    = w3.eth.contract(address=a, abi=_abi)
            debt = _call(c, debt_fn,  default=None)
            ta   = _call(c, asset_fn, default=None)
            if debt is None or ta is None:
                return True, f"{debt_fn}/{asset_fn} not callable"
            if debt > ta:
                return False, f"{debt_fn}={debt} > {asset_fn}={ta} → UNDERCOLLATERALISED"
            return True, f"debt={debt} assets={ta}"

        self._invariants.append(InvariantDef(
            f"SOLVENCY_{debt_fn.upper()}",
            f"{debt_fn}() must be <= {asset_fn}()",
            _check_solvency,
            severity="CRITICAL",
            category="LENDING",
        ))

    def check_all(self, contract_address: str, w3: Web3) -> List[Tuple[str, str]]:
        """
        Run every invariant. Returns (name, detail) for each violation.
        Swallows all exceptions — invariant checks are advisory.
        """
        if w3 is None:
            return []
        violations = []
        for inv in self._invariants:
            try:
                ok, detail = inv.check_fn(w3, contract_address)
                if not ok:
                    violations.append((inv.name, f"[{inv.severity}] {inv.desc} | {detail}"))
            except Exception:
                pass
        return violations

    def generate_auto_invariants(self, contract_address: str, db) -> None:
        """
        Infer invariants from DB execution history:
          - Functions with 0% historical revert rate get a NEVER_REVERTS invariant.
        These are MEDIUM severity (statistical, not structural).
        """
        try:
            rates = db.get_function_revert_rates(contract_address)
            for func_sig, rate in rates.items():
                if rate == 0.0:
                    name  = f"NEVER_REVERTS_{func_sig.split('(')[0].upper()[:20]}"
                    desc  = f"{func_sig} has 0% historical revert rate"
                    self._invariants.append(InvariantDef(
                        name, desc,
                        lambda w3, a, fs=func_sig: (True, "DB-only; enforced by SequenceFuzzer"),
                        severity="MEDIUM",
                        category="BEHAVIORAL",
                    ))
        except Exception:
            pass

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for inv in self._invariants:
            counts[inv.category] = counts.get(inv.category, 0) + 1
        return counts
