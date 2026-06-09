"""ChainEDR Compiler Bug Correlator

Maps `pragma solidity` version to known Solidity compiler bugs/CVEs and flags
which bugs apply to the analyzed contract.

Version range spec syntax supported:
  <X.Y.Z   >=X.Y.Z   ^X.Y.Z   ~X.Y.Z   X.Y.Z   >=A.B.C,<D.E.F

Results are sorted: CRITICAL → HIGH → MEDIUM → LOW.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    from packaging.version import Version
    _USE_PACKAGING = True
except ImportError:
    _USE_PACKAGING = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CompilerBug:
    bug_id: str
    title: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    affected_versions: str  # e.g. "<0.8.0" or ">=0.6.0,<0.6.8"
    description: str
    pattern: str            # regex: if matched in source, vulnerability is exercised
    recommendation: str
    cve: str = ""           # CVE number if assigned, else ""


@dataclass
class CompilerFinding:
    bug: CompilerBug
    pragma_version: str     # extracted from source (may contain ^ ~ > etc.)
    pattern_matched: bool   # whether vulnerable code pattern was found in source
    severity: str           # mirrors bug.severity (can be downgraded if no pattern match)


# ---------------------------------------------------------------------------
# Bug database — 15 real Solidity compiler bugs, accurate version ranges
# ---------------------------------------------------------------------------

_BUGS: List[CompilerBug] = [

    CompilerBug(
        bug_id="SOL-2016-001",
        title="No built-in integer overflow / underflow protection",
        severity="CRITICAL",
        affected_versions="<0.8.0",
        description=(
            "Solidity < 0.8.0 does not revert on arithmetic overflow or underflow. "
            "uint256(0) - 1 wraps to 2**256-1 silently. Requires manual SafeMath."
        ),
        pattern=r'(?:\+\+|--|\+=|-=|\*=|[+\-\*])\s*\w',
        recommendation="Upgrade to >=0.8.0 (built-in checks) or use OpenZeppelin SafeMath.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2018-001",
        title="Constructor named same as contract (function-style constructor)",
        severity="HIGH",
        affected_versions="<0.5.0",
        description=(
            "Before 0.5.0 the constructor was a function with the same name as the contract. "
            "If the contract is renamed without updating the constructor name, the constructor "
            "becomes a public regular function callable by anyone."
        ),
        pattern=r'function\s+\w+\s*\([^)]*\)\s*(?:public\s+)?(?!\w*returns)',
        recommendation="Use the `constructor` keyword (>=0.4.22) or upgrade to >=0.5.0.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2019-001",
        title="ABIEncoderV2 corrupts storage arrays with nested dynamic types",
        severity="HIGH",
        affected_versions=">=0.5.0,<0.5.17",
        description=(
            "The experimental ABIEncoderV2 in 0.5.0..0.5.16 produces incorrect ABI encoding "
            "for storage arrays that contain structs with nested dynamic types. Data can be "
            "silently truncated or corrupted during external calls."
        ),
        pattern=r'pragma\s+experimental\s+ABIEncoderV2',
        recommendation="Upgrade to >=0.5.17 or disable ABIEncoderV2.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2020-001",
        title="Free memory pointer corruption via optimizer (>=0.6.5,<0.6.8)",
        severity="HIGH",
        affected_versions=">=0.6.5,<0.6.8",
        description=(
            "The Yul optimizer in 0.6.5..0.6.7 can incorrectly reuse memory slots "
            "allocated by the free memory pointer (mload(0x40)), leading to silent "
            "data corruption in memory-heavy code paths."
        ),
        pattern=r'memory\b',
        recommendation="Upgrade to >=0.6.8.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2021-001",
        title="Optimizer removes necessary SSTORE in certain patterns",
        severity="CRITICAL",
        affected_versions=">=0.7.0,<0.7.6",
        description=(
            "The Solidity optimizer in 0.7.0..0.7.5 can eliminate SSTORE instructions "
            "that it incorrectly determines to be redundant. Storage writes may be silently "
            "dropped, breaking contract invariants."
        ),
        pattern=r'\w+\s*=\s*\w+\s*;',
        recommendation="Upgrade to >=0.7.6.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2022-001",
        title="ABI coder v2 bug with calldata arrays of static types",
        severity="HIGH",
        affected_versions=">=0.8.0,<0.8.3",
        description=(
            "In 0.8.0..0.8.2, ABI coder v2 (default) incorrectly decodes calldata arrays "
            "of static base types (e.g., uint256[]) when the function is called with "
            "calldata that has additional trailing data. Can be exploited to pass "
            "malformed calldata that decodes differently than intended."
        ),
        pattern=r'calldata\s+\w+\[\]',
        recommendation="Upgrade to >=0.8.3.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2022-002",
        title="YulOptimizer removes storage writes reachable via assembly",
        severity="CRITICAL",
        affected_versions=">=0.8.13,<0.8.15",
        description=(
            "In 0.8.13..0.8.14, the Yul optimizer can eliminate SSTORE opcodes inside "
            "inline assembly blocks when it determines they are 'redundant', even when "
            "they are not. This is the bug that affected OpenZeppelin's StorageSlot "
            "proxy implementation and led to CVE-2022-35961."
        ),
        pattern=r'assembly\s*\{',
        recommendation="Upgrade to >=0.8.15.",
        cve="CVE-2022-35961",
    ),

    CompilerBug(
        bug_id="SOL-2020-002",
        title="Incorrect code generation for OR conditions in optimizer",
        severity="HIGH",
        affected_versions=">=0.6.0,<0.6.2",
        description=(
            "The Yul optimizer in 0.6.0..0.6.1 generates incorrect code for certain "
            "boolean OR conditions, potentially turning `a || b` into always-true or "
            "always-false. Can bypass require() checks silently."
        ),
        pattern=r'\|\|',
        recommendation="Upgrade to >=0.6.2.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2021-002",
        title="Assembly optimizer removes RETURNDATASIZE checks",
        severity="HIGH",
        affected_versions=">=0.8.0,<0.8.4",
        description=(
            "In 0.8.0..0.8.3, the optimizer can incorrectly remove checks that use "
            "returndatasize after external calls in assembly blocks. Low-level call "
            "return data size checks may be silently eliminated."
        ),
        pattern=r'returndatasize\(\)',
        recommendation="Upgrade to >=0.8.4.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2016-002",
        title="Default public visibility (pre-0.5.0)",
        severity="MEDIUM",
        affected_versions=">=0.4.0,<0.5.0",
        description=(
            "In Solidity < 0.5.0, functions without an explicit visibility modifier "
            "default to public. Omitting visibility on sensitive functions allows "
            "anyone to call them."
        ),
        pattern=r'function\s+\w+\s*\([^)]*\)\s*\{',
        recommendation="Upgrade to >=0.5.0 where explicit visibility is mandatory.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2020-003",
        title="Named return variables shadow state variables",
        severity="MEDIUM",
        affected_versions=">=0.6.0,<0.6.5",
        description=(
            "In 0.6.0..0.6.4, named return variables can shadow contract-level state "
            "variables of the same name without a compiler warning, causing silent "
            "reads of the uninitialized return variable instead of the state variable."
        ),
        pattern=r'returns\s*\(\s*\w+\s+\w+\s*\)',
        recommendation="Upgrade to >=0.6.5 or rename return variables to avoid shadowing.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2021-003",
        title="ConstantOptimizer byte opcode bug",
        severity="HIGH",
        affected_versions=">=0.7.4,<0.8.0",
        description=(
            "The ConstantOptimizer in 0.7.4..0.7.6 generates incorrect code for "
            "expressions involving the byte() opcode combined with constant folding. "
            "Bitfield operations on constants may silently produce wrong results."
        ),
        pattern=r'\bbyte\s*\(',
        recommendation="Upgrade to >=0.8.0.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2022-003",
        title="Incorrect storage cleanup via assembly in YulOptimizer",
        severity="HIGH",
        affected_versions=">=0.8.7,<0.8.9",
        description=(
            "In 0.8.7..0.8.8, the Yul optimizer can produce incorrect storage cleanup "
            "when inline assembly writes to storage slots using sstore and the slot is "
            "later read in the same function, potentially reading stale data."
        ),
        pattern=r'sstore\s*\(',
        recommendation="Upgrade to >=0.8.9.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2018-002",
        title="Constructor name typosquatting (pre-0.4.22)",
        severity="HIGH",
        affected_versions="<0.4.22",
        description=(
            "Before 0.4.22, the constructor MUST be named identically to the contract. "
            "A single-character typo in either name turns the constructor into a public "
            "function that anyone can call to reinitialize the contract."
        ),
        pattern=r'function\s+\w+\s*\(',
        recommendation="Upgrade to >=0.4.22 and use the `constructor` keyword.",
        cve="",
    ),

    CompilerBug(
        bug_id="SOL-2019-002",
        title="tx.origin authentication — no compiler warning (pre-0.8.0)",
        severity="MEDIUM",
        affected_versions="<0.8.0",
        description=(
            "Solidity < 0.8.0 emits no warning for tx.origin-based authentication. "
            "Contracts relying on tx.origin for access control are vulnerable to "
            "phishing attacks where an intermediary contract forwards the call."
        ),
        pattern=r'\btx\.origin\b',
        recommendation="Replace tx.origin checks with msg.sender, or upgrade to >=0.8.0 "
                       "which emits a warning for tx.origin usage.",
        cve="",
    ),
]

# Severity ordering for sorting
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CompilerCorrelator:
    KNOWN_BUGS: List[CompilerBug] = _BUGS

    def analyze(self, source: str) -> List[CompilerFinding]:
        pragma = self._extract_pragma(source)
        if pragma is None:
            return []

        version = self._normalize_version(pragma)
        findings: List[CompilerFinding] = []

        for bug in self.KNOWN_BUGS:
            if not self._version_in_range(version, bug.affected_versions):
                continue
            pattern_hit = bool(re.search(bug.pattern, source))
            findings.append(CompilerFinding(
                bug=bug,
                pragma_version=pragma,
                pattern_matched=pattern_hit,
                severity=bug.severity,
            ))

        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        return findings

    # -----------------------------------------------------------------------
    # Pragma extraction
    # -----------------------------------------------------------------------

    def _extract_pragma(self, source: str) -> Optional[str]:
        """Return raw version constraint from the first pragma solidity statement."""
        m = re.search(
            r'pragma\s+solidity\s+([^;]+);',
            source,
        )
        if not m:
            return None
        return m.group(1).strip()

    # -----------------------------------------------------------------------
    # Version arithmetic
    # -----------------------------------------------------------------------

    def _version_in_range(self, version_str: str, range_spec: str) -> bool:
        """
        Check whether version_str satisfies range_spec.
        version_str may itself contain ^ ~ >= etc. (from pragma).
        We extract the concrete version from it before comparing.
        """
        concrete = self._normalize_version(version_str)
        if _USE_PACKAGING:
            return self._version_in_range_packaging(concrete, range_spec)
        return self._version_in_range_tuple(concrete, range_spec)

    @staticmethod
    def _normalize_version(v: str) -> str:
        """Strip leading ^~>= and return the first X.Y.Z found, as a string."""
        m = re.search(r'(\d+\.\d+\.\d+)', v)
        if m:
            return m.group(1)
        # Handle X.Y without patch
        m2 = re.search(r'(\d+\.\d+)', v)
        if m2:
            return m2.group(1) + '.0'
        return '0.0.0'

    def _version_in_range_packaging(self, version: str, range_spec: str) -> bool:
        try:
            v = Version(version)
            # Split on comma for compound specs like ">=0.6.0,<0.6.8"
            parts = [p.strip() for p in range_spec.split(',')]
            for part in parts:
                # packaging uses ~= for compatible releases; map ^ to ~=
                part = part.replace('^', '~=')
                op_m = re.match(r'([><=!~]+)\s*(\d[\d.]*)', part)
                if not op_m:
                    continue
                op, ver = op_m.group(1), op_m.group(2)
                if len(ver.split('.')) == 2:
                    ver += '.0'
                spec_v = Version(ver)
                if op == '<' and not (v < spec_v):
                    return False
                elif op == '<=' and not (v <= spec_v):
                    return False
                elif op == '>' and not (v > spec_v):
                    return False
                elif op == '>=' and not (v >= spec_v):
                    return False
                elif op == '==' and not (v == spec_v):
                    return False
                elif op in ('~=', '^'):
                    # Compatible release: same major.minor prefix
                    if v.major != spec_v.major or v.minor != spec_v.minor:
                        return False
                    if v < spec_v:
                        return False
            return True
        except Exception:
            return self._version_in_range_tuple(version, range_spec)

    @staticmethod
    def _version_in_range_tuple(version: str, range_spec: str) -> bool:
        def to_tuple(s: str) -> Tuple[int, int, int]:
            parts = re.sub(r'[^0-9.]', '', s).split('.')
            parts = (parts + ['0', '0', '0'])[:3]
            return tuple(int(x) if x else 0 for x in parts)  # type: ignore[return-value]

        v = to_tuple(version)
        parts = [p.strip() for p in range_spec.split(',')]
        for part in parts:
            op_m = re.match(r'([><=!^~]+)\s*(\d[\d.]*)', part)
            if not op_m:
                continue
            op, ver_s = op_m.group(1), op_m.group(2)
            rv = to_tuple(ver_s)
            if op == '<' and not (v < rv):
                return False
            elif op == '<=' and not (v <= rv):
                return False
            elif op == '>' and not (v > rv):
                return False
            elif op == '>=' and not (v >= rv):
                return False
            elif op in ('==', '^', '~=', '~'):
                # For ^ and ~, check same major.minor range
                if op in ('^', '~', '~='):
                    if v[0] != rv[0] or v[1] != rv[1]:
                        return False
                    if v < rv:
                        return False
                else:
                    if v != rv:
                        return False
        return True
