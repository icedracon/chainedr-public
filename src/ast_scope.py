"""
ChainEDR — AST Scope Extractor

Replaces naive regex-over-whole-file with proper function-boundary-aware
analysis. Uses brace matching (O(n)) to extract exact function bodies,
modifiers, visibility, and state mutability.

Why this matters:
  Old approach: grep 'updatedAt' anywhere in file → FP if one contract
                has it but another doesn't validate it
  New approach: per-function analysis → only fires when the specific
                function containing the dangerous call lacks the guard

Usage:
    from src.ast_scope import extract_functions, FunctionInfo

    fns = extract_functions(source_code)
    for fn in fns:
        if 'latestRoundData' in fn.body:
            if not fn.has_guard('updatedAt'):
                report(fn)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


# ─── Data model ──────────────────────────────────────────────────────────────

@dataclass
class FunctionInfo:
    name: str
    visibility: str          # public / external / internal / private
    mutability: str          # view / pure / payable / nonpayable
    modifiers: List[str]     # e.g. ['onlyOwner', 'nonReentrant', 'whenNotPaused']
    params: str              # raw parameter string
    body: str                # everything between the outermost { }
    start: int               # char offset in source
    end: int                 # char offset in source
    is_constructor: bool = False

    # ── Convenience helpers ──────────────────────────────────────────────────

    def has_guard(self, *patterns: str) -> bool:
        """True if any pattern appears in the function body."""
        return any(p in self.body for p in patterns)

    def has_regex_guard(self, pattern: str, flags: int = re.I) -> bool:
        return bool(re.search(pattern, self.body, flags))

    def calls(self, fn_name: str) -> bool:
        return bool(re.search(rf'\b{re.escape(fn_name)}\s*\(', self.body))

    def has_modifier(self, *mod_names: str) -> bool:
        return any(m in self.modifiers for m in mod_names)

    def is_protected(self) -> bool:
        """Heuristic: does the function have any access control modifier?"""
        COMMON_ACL = {
            'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyCoreRole',
            'onlyGovernor', 'onlyGuardian', 'onlyKeeper',
            'requiresAuth', 'authorized', 'restricted',
        }
        return bool(self.modifiers & COMMON_ACL if isinstance(self.modifiers, set)
                    else any(m in COMMON_ACL for m in self.modifiers))

    def reads_storage(self, var: str) -> bool:
        return bool(re.search(rf'\b{re.escape(var)}\b', self.body))


@dataclass
class ContractInfo:
    name: str
    kind: str               # contract / interface / library / abstract
    inherits: List[str]
    functions: List[FunctionInfo]
    source: str             # full contract source (between outer braces)
    start: int
    end: int

    def get_function(self, name: str) -> Optional[FunctionInfo]:
        for f in self.functions:
            if f.name == name:
                return f
        return None

    def external_functions(self) -> List[FunctionInfo]:
        return [f for f in self.functions if f.visibility in ('public', 'external')]

    def internal_functions(self) -> List[FunctionInfo]:
        return [f for f in self.functions if f.visibility in ('internal', 'private')]


# ─── Brace matcher ───────────────────────────────────────────────────────────

def _find_matching_brace(src: str, open_pos: int) -> int:
    """
    Given the position of '{', return the position of the matching '}'.
    Skips string literals and comments.
    Returns -1 if not found.
    """
    depth = 0
    i = open_pos
    n = len(src)
    in_string_single = False
    in_string_double = False
    in_comment_line = False
    in_comment_block = False

    while i < n:
        c = src[i]

        # Line comment
        if not in_string_single and not in_string_double and not in_comment_block:
            if c == '/' and i + 1 < n and src[i + 1] == '/':
                in_comment_line = True
                i += 2
                continue

        if in_comment_line:
            if c == '\n':
                in_comment_line = False
            i += 1
            continue

        # Block comment
        if not in_string_single and not in_string_double:
            if c == '/' and i + 1 < n and src[i + 1] == '*':
                in_comment_block = True
                i += 2
                continue

        if in_comment_block:
            if c == '*' and i + 1 < n and src[i + 1] == '/':
                in_comment_block = False
                i += 2
                continue
            i += 1
            continue

        # String literals
        if c == '"' and not in_string_single:
            in_string_double = not in_string_double
        elif c == "'" and not in_string_double:
            in_string_single = not in_string_single

        if not in_string_single and not in_string_double:
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i

        i += 1

    return -1


# ─── Function extractor ───────────────────────────────────────────────────────

# Matches: function name(params) visibility mutability modifiers... {
_FN_HEADER = re.compile(
    r'\b(function)\s+(\w+)\s*(\([^)]*\))'   # function name(params)
    r'([^{;]*)',                              # everything up to { or ;
    re.S
)

# Matches: constructor(params) modifiers... {
_CTOR_HEADER = re.compile(
    r'\bconstructor\s*(\([^)]*\))'
    r'([^{;]*)',
    re.S
)

_VISIBILITY = re.compile(r'\b(public|external|internal|private)\b')
_MUTABILITY = re.compile(r'\b(view|pure|payable)\b')
_MODIFIER_CALL = re.compile(r'\b([a-zA-Z_]\w*)\s*(?:\([^)]*\))?\s*(?=\b)')

# Words that are not modifier calls
_KEYWORDS = frozenset({
    'public', 'external', 'internal', 'private',
    'view', 'pure', 'payable', 'virtual', 'override',
    'returns', 'memory', 'calldata', 'storage',
    'function', 'constructor', 'modifier', 'event', 'error',
    'uint256', 'uint128', 'uint64', 'uint32', 'uint16', 'uint8', 'uint',
    'int256', 'int128', 'int64', 'int32', 'int16', 'int8', 'int',
    'bool', 'address', 'bytes', 'bytes32', 'string',
    'emit', 'return', 'if', 'else', 'for', 'while', 'do',
    'mapping', 'struct', 'enum',
})


def _parse_header_modifiers(header: str) -> List[str]:
    """Extract modifier names from a function header (after param list)."""
    mods = []
    # Strip visibility/mutability/virtual/override keywords
    for tok in re.findall(r'\b([a-zA-Z_]\w*)\b', header):
        if tok not in _KEYWORDS:
            mods.append(tok)
    return mods


def extract_functions(source: str) -> List[FunctionInfo]:
    """
    Extract all function definitions from a Solidity source string.
    Returns FunctionInfo objects with exact body text.
    """
    functions: List[FunctionInfo] = []

    # Process regular functions
    for m in _FN_HEADER.finditer(source):
        header_end = m.end()
        # Find the opening brace (may be right after header or separated by whitespace)
        brace_pos = source.find('{', header_end)
        if brace_pos == -1:
            continue
        # Check nothing suspicious between header end and brace (e.g. semicolons = abstract)
        between = source[header_end:brace_pos]
        if ';' in between:
            continue

        close_pos = _find_matching_brace(source, brace_pos)
        if close_pos == -1:
            continue

        body = source[brace_pos + 1:close_pos]
        header_str = m.group(4)  # everything after params up to {

        vis_m = _VISIBILITY.search(header_str)
        mut_m = _MUTABILITY.search(header_str)

        functions.append(FunctionInfo(
            name=m.group(2),
            visibility=vis_m.group(1) if vis_m else 'internal',
            mutability=mut_m.group(1) if mut_m else 'nonpayable',
            modifiers=_parse_header_modifiers(header_str),
            params=m.group(3),
            body=body,
            start=m.start(),
            end=close_pos,
        ))

    # Process constructors
    for m in _CTOR_HEADER.finditer(source):
        header_end = m.end()
        brace_pos = source.find('{', header_end)
        if brace_pos == -1:
            continue
        between = source[header_end:brace_pos]
        if ';' in between:
            continue
        close_pos = _find_matching_brace(source, brace_pos)
        if close_pos == -1:
            continue

        body = source[brace_pos + 1:close_pos]
        header_str = m.group(2)

        functions.append(FunctionInfo(
            name='constructor',
            visibility='public',
            mutability='nonpayable',
            modifiers=_parse_header_modifiers(header_str),
            params=m.group(1),
            body=body,
            start=m.start(),
            end=close_pos,
            is_constructor=True,
        ))

    # Sort by position in source
    functions.sort(key=lambda f: f.start)
    return functions


# ─── Contract extractor ──────────────────────────────────────────────────────

_CONTRACT_HEADER = re.compile(
    r'\b(contract|interface|library|abstract\s+contract)\s+(\w+)'
    r'(?:\s+is\s+([^{]+))?'
    r'\s*\{',
    re.S
)


def extract_contracts(source: str) -> List[ContractInfo]:
    """
    Extract all contract/interface/library definitions.
    Each ContractInfo contains its extracted functions.
    """
    contracts: List[ContractInfo] = []

    for m in _CONTRACT_HEADER.finditer(source):
        brace_pos = m.end() - 1  # the { is included in the match
        close_pos = _find_matching_brace(source, brace_pos)
        if close_pos == -1:
            continue

        contract_src = source[brace_pos + 1:close_pos]
        inherits_raw = m.group(3) or ''
        inherits = [i.strip().split('(')[0].strip()
                    for i in inherits_raw.split(',') if i.strip()]

        kind_raw = m.group(1).strip()
        kind = 'abstract' if 'abstract' in kind_raw else kind_raw

        contracts.append(ContractInfo(
            name=m.group(2),
            kind=kind,
            inherits=inherits,
            functions=extract_functions(contract_src),
            source=contract_src,
            start=m.start(),
            end=close_pos,
        ))

    return contracts


# ─── File-level helper ───────────────────────────────────────────────────────

def parse_file(source: str) -> dict:
    """
    Parse a single Solidity file.

    Returns:
        {
          'contracts': List[ContractInfo],
          'all_functions': List[FunctionInfo],   # flattened
          'function_map': {fn_name: FunctionInfo},
        }
    """
    contracts = extract_contracts(source)
    all_fns: List[FunctionInfo] = []
    fn_map: dict = {}
    for c in contracts:
        for f in c.functions:
            all_fns.append(f)
            fn_map[f'{c.name}.{f.name}'] = f
            fn_map[f.name] = f  # last-write wins for simple lookup

    return {
        'contracts': contracts,
        'all_functions': all_fns,
        'function_map': fn_map,
    }


# ─── Guard checkers (shared logic for detectors) ─────────────────────────────

def has_staleness_guard(fn: FunctionInfo) -> bool:
    """True if function validates Chainlink updatedAt against a threshold."""
    GATES = [
        r'require\s*\([^;]*updatedAt',
        r'revert\s+\w*[Ss]tale',
        r'block\.timestamp\s*-\s*updatedAt',
        r'block\.timestamp\.sub\s*\(\s*updatedAt',
        r'updatedAt\s*\+\s*\w+',        # updatedAt + heartbeat
        r'StalePrice\s*\(',
        r'[Ss]tale[Pp]rice',
        r'assert\s*\([^;]*updatedAt',
    ]
    return any(fn.has_regex_guard(p) for p in GATES)


def has_reentrancy_guard(fn: FunctionInfo) -> bool:
    """True if function has nonReentrant or equivalent guard."""
    GUARDS = {'nonReentrant', 'noReentrant', 'reentrancyGuard', 'ReentrancyGuard'}
    if fn.has_modifier(*GUARDS):
        return True
    # Also check for mutex pattern in body
    return fn.has_regex_guard(r'_status\s*==\s*_NOT_ENTERED|_entered\s*=\s*true')


def has_slippage_guard(fn: FunctionInfo) -> bool:
    """True if function enforces minimum output (slippage protection)."""
    return fn.has_regex_guard(
        r'(?:minOut|minAmount|minReturn|amountOutMin|_min|minimum)'
        r'|require\s*\([^;]*>=\s*min'
    )


def has_access_control(fn: FunctionInfo) -> bool:
    """True if function has any access control."""
    if fn.visibility in ('internal', 'private'):
        return True
    if fn.has_modifier('onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyCoreRole',
                        'onlyGovernor', 'requiresAuth', 'authorized'):
        return True
    return fn.has_regex_guard(r'require\s*\([^;]*(?:owner|admin|role|auth|access)')


def has_partial_buffer_consume(fn: FunctionInfo, buf_var: str, loss_var: str) -> bool:
    """
    True if function burns buf_var AND subtracts it from loss_var
    before the downstream applyLosses call — i.e. the waterfall cliff is fixed.
    """
    burn_pattern = rf'\.burn\s*\(\s*{re.escape(buf_var)}\s*\)'
    sub_pattern  = rf'{re.escape(loss_var)}\s*-=\s*{re.escape(buf_var)}'
    return fn.has_regex_guard(burn_pattern) and fn.has_regex_guard(sub_pattern)
