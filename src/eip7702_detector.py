"""
ChainEDR EIP-7702 Account Abstraction Detector

Static analysis for EIP-7702 (Pectra, May 2025) vulnerabilities.
EIP-7702 allows EOAs to delegate code execution to smart contracts via
SET_CODE_TX_TYPE (0x04), breaking fundamental assumptions in existing
Solidity code:

  - EOAs can now execute arbitrary code during callbacks
  - tx.origin == msg.sender no longer guarantees "caller is a plain EOA"
  - address.code.length == 0 no longer means "not a contract"

These patterns appear in real Solidity code, but generic analyzers usually do
not model the delegated-account boundary directly. ChainEDR treats them as
candidate 7702/4337 signals that need semantic filtering and, where possible,
dynamic proof.

Checks (21 core EIP-7702 signals):
  AA7702-001  TX_ORIGIN_IS_EOA_BYPASS        — tx.origin == msg.sender is broken
  AA7702-002  ISCONTRACT_EOA_ASSUMPTION      — isContract/code.length==0 is broken
  AA7702-003  CALLBACK_REENTRANCY_VIA_EOA    — EOA callbacks can now run code
  AA7702-004  CROSS_CHAIN_DELEGATION_REPLAY  — chain_id=0 allows all-chain replay
  AA7702-005  MISSING_DELEGATION_REVOCATION  — no mechanism to un-delegate
  AA7702-006  DELEGATECALL_FROM_DELEGATED    — delegatecall in delegation target
  AA7702-007  STORAGE_COLLISION_DELEGATION   — delegation target assumes own storage
  AA7702-008  INITIALIZATION_RACE            — delegation target init not atomic
  AA7702-009  PROXY_DELEGATION_CONFLICT      — ERC-1967 proxy + 7702 delegation clash
  AA7702-010  PERMIT_BYPASS_VIA_DELEGATION   — ERC-20 permit broken by delegated EOA
  AA7702-011  BATCH_AUTH_ORDERING            — batch authorization reorder/replay
  AA7702-012  NONCE_GAP_EXPLOITATION         — 7702 auth nonce diverges from tx nonce
  AA7702-013  GAS_SPONSORSHIP_GRIEFING       — delegation target unbounded gas use
  AA7702-014  VALUE_TRANSFER_CONFUSION       — ETH to delegating EOA triggers code
  AA7702-015  SELFDESTRUCT_DELEGATION_TARGET — selfdestruct in delegation target
  AA7702-016  ECRECOVER_DELEGATION_CONTEXT   — signature checks assume dumb EOA
  AA7702-017  ERC777_HOOK_DELEGATION         — ERC-777 hooks + delegation = new reentrancy
  AA7702-018  APPROVAL_FRONTRUN_DELEGATION   — approve+transferFrom via delegated EOA
  AA7702-019  HARDCODED_SINGLE_RELAYER       — single relayer = account liveness risk
  AA7702-020  MISSING_STORAGE_NAMESPACE      — no ERC-7201 = storage collision on redelegation
  AA7702-021  ENTRYPOINT_VERSION_MISMATCH    — hardcoded EntryPoint v0.6 breaks v0.7+ users

Reference: https://eips.ethereum.org/EIPS/eip-7702
Activation: Ethereum Pectra upgrade, May 7 2025
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    from .eip7702_sandbox import (
        PreBehaviorTrace,
        SandboxPolicy,
        build_pre_behavior_trace,
    )
except ImportError:
    from eip7702_sandbox import (
        PreBehaviorTrace,
        SandboxPolicy,
        build_pre_behavior_trace,
    )


@dataclass
class EIP7702Finding:
    check_id: str
    title: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    description: str
    location: str
    cwe: str
    recommendation: str
    confidence: float       # 0.0-1.0
    eip7702_specific: bool = True
    sandbox_policy: Optional[SandboxPolicy] = None
    pre_behavior_trace: Optional[PreBehaviorTrace] = None
    sandbox_boundary: str = ""
    sandbox_bypass_class: str = ""
    semantic_context: Dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.pre_behavior_trace is None:
            self.pre_behavior_trace = build_pre_behavior_trace(
                self.check_id,
                title=self.title,
                location=self.location,
                description=self.description,
                confidence=self.confidence,
            )
        if self.sandbox_policy is None:
            self.sandbox_policy = self.pre_behavior_trace.policy
        if not self.sandbox_boundary:
            self.sandbox_boundary = self.pre_behavior_trace.violated_boundary
        if not self.sandbox_bypass_class:
            self.sandbox_bypass_class = self.pre_behavior_trace.bypass_class

    def sandbox_metadata(self) -> dict:
        return {
            "sandbox_policy": self.sandbox_policy.to_dict() if self.sandbox_policy else {},
            "pre_behavior_trace": (
                self.pre_behavior_trace.to_dict() if self.pre_behavior_trace else {}
            ),
            "sandbox_boundary": self.sandbox_boundary,
            "sandbox_bypass_class": self.sandbox_bypass_class,
            "eip7702_specific": self.eip7702_specific,
        }

    def proof_metadata(self) -> dict:
        return proof_metadata_for_check(self.check_id, self.semantic_context)

    def to_dict(self) -> dict:
        data = {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "location": self.location,
            "cwe": self.cwe,
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 2),
        }
        data.update(self.sandbox_metadata())
        if self.semantic_context:
            data["semantic_context"] = self.semantic_context
        data["proof_recipe"] = self.proof_metadata()
        try:
            from .reviewer_confidence import attach_reviewer_confidence
        except ImportError:
            from reviewer_confidence import attach_reviewer_confidence

        attach_reviewer_confidence(data)
        return data


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _strip_comments(source: str) -> str:
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return source


def _enclosing_function(lines: list[str], line_idx: int) -> str:
    fn_re = re.compile(r"^\s*function\s+(\w+)\s*\(")
    for i in range(line_idx, -1, -1):
        m = fn_re.match(lines[i])
        if m:
            return m.group(1)
    return "unknown"


def _is_in_comment_or_string(line: str, match_start: int) -> bool:
    """Check if match position is inside a string literal."""
    in_single = False
    in_double = False
    for i in range(match_start):
        if line[i] == "'" and not in_double:
            in_single = not in_single
        elif line[i] == '"' and not in_single:
            in_double = not in_double
    return in_single or in_double


# Modifiers that gate function entry. If a function carries one of these, it is
# not an unauthenticated public surface; many 7702 findings then become defence-
# in-depth observations on a function that the caller doesn't control. Anything
# starting with "only" is also treated as a guard.
_GUARD_MODIFIER_NAMES = frozenset({
    # Generic ownership / role gates
    "onlyowner", "onlyadmin", "onlyrole", "onlymanager", "onlycontroller",
    "onlyfactory", "onlyminter", "onlyoperator", "onlyauthorized",
    "onlygovernance", "onlytrusted", "onlywhitelisted", "onlyallowed",
    # AA / 7702 / 4337 specific
    "onlyentrypoint", "onlydelegate", "onlydelegatecaller",
    "onlymodule", "onlyhook", "onlyvalidator", "onlybundler", "onlypaymaster",
    "onlyaccount", "onlywallet",
    # Common library aliases
    "auth", "authorized", "restricted", "protected", "guard",
    # Initialization guards
    "initializer", "reinitializer",
})


def _function_signature_modifiers(lines: list[str], line_idx: int) -> list[str]:
    """Lower-cased modifier list of the enclosing function (best-effort).

    Walks back to the enclosing ``function NAME(`` line, then collects the
    tokens between the close of the parameter list and the opening ``{`` of
    the body. Visibility/mutability keywords are filtered out. Multi-line
    signatures are supported. Returns ``[]`` if no enclosing function is found
    or if the signature can't be parsed — callers MUST treat an empty list
    as "no guard detected" rather than as a positive suppression signal.
    """
    fn_open_re = re.compile(r"^\s*function\s+\w+\s*\(")
    fn_start = -1
    for i in range(line_idx, -1, -1):
        if fn_open_re.match(lines[i]):
            fn_start = i
            break
    if fn_start < 0:
        return []

    buf: list[str] = []
    for j in range(fn_start, min(fn_start + 30, len(lines))):
        buf.append(lines[j])
        if "{" in lines[j] or lines[j].rstrip().endswith(";"):
            break
    sig = " ".join(buf)

    open_idx = sig.find("(")
    if open_idx < 0:
        return []
    depth = 0
    close_idx = -1
    for k in range(open_idx, len(sig)):
        if sig[k] == "(":
            depth += 1
        elif sig[k] == ")":
            depth -= 1
            if depth == 0:
                close_idx = k
                break
    if close_idx < 0:
        return []
    brace_idx = sig.find("{", close_idx)
    if brace_idx < 0:
        brace_idx = len(sig)

    tail = sig[close_idx + 1: brace_idx]
    # Drop modifier-arg parens so onlyRole(ADMIN_ROLE) collapses to onlyRole.
    cleaned = re.sub(r"\([^()]*\)", "", tail)

    skip = {
        "public", "private", "internal", "external",
        "view", "pure", "payable", "virtual", "override", "returns",
    }
    modifiers: list[str] = []
    for tok in re.findall(r"[A-Za-z_]\w*", cleaned):
        low = tok.lower()
        if low in skip:
            continue
        modifiers.append(low)
    return modifiers


def _function_has_guard_modifier(
    lines: list[str], line_idx: int
) -> Optional[str]:
    """Return the guard modifier name if the enclosing function is gated.

    Recognises the curated ``_GUARD_MODIFIER_NAMES`` set plus any modifier
    whose lower-cased name starts with ``only`` (a strong Solidity convention
    for access control). Returns ``None`` when no guard is detected so the
    caller continues firing.
    """
    for mod in _function_signature_modifiers(lines, line_idx):
        if mod in _GUARD_MODIFIER_NAMES or mod.startswith("only"):
            return mod
    return None


# Inline access-control patterns. Many production functions are guarded by an
# explicit `require(msg.sender == owner)` rather than a modifier. To a regex
# pattern check, those functions look unguarded; semantically they are gated.
# Recognising the common shapes here halves FP rate on real audited code where
# inheritance from Ownable / AccessControl is preferred over modifier sugar.
_INLINE_AUTH_PATTERNS = (
    re.compile(r"require\s*\(\s*msg\.sender\s*==\s*(owner|_owner|admin|_admin|governance|_governance|manager|controller|guardian)"),
    re.compile(r"require\s*\(\s*(owner|_owner|admin|_admin|governance|_governance|manager|controller)\s*==\s*msg\.sender"),
    re.compile(r"require\s*\(\s*hasRole\s*\("),
    re.compile(r"require\s*\(\s*_?(isOwner|isAdmin|isAuthorized|isOperator|isManager)\s*\("),
    re.compile(r"_check(Owner|Role|Auth|Authorized|Admin|Manager)\s*\("),
    re.compile(r"if\s*\(\s*msg\.sender\s*!=\s*(owner|_owner|admin|_admin)\s*\)\s*revert"),
    re.compile(r"require\s*\(\s*authorized\s*\[\s*msg\.sender\s*\]"),
    re.compile(r"require\s*\(\s*operators\s*\[\s*msg\.sender\s*\]"),
)


def _function_has_inline_auth(
    lines: list[str], line_idx: int
) -> Optional[str]:
    """Return the inline auth pattern if the enclosing function checks it.

    Looks at the body of the function enclosing ``line_idx`` for any
    ``require``/``if revert`` that establishes an access-control boundary
    (owner/admin/role/operators map). Returns the first matching pattern's
    source for transparency, or ``None``.
    """
    # Locate enclosing function header
    fn_open_re = re.compile(r"^\s*function\s+\w+\s*\(")
    header_idx = -1
    for i in range(line_idx, -1, -1):
        if fn_open_re.match(lines[i]):
            header_idx = i
            break
    if header_idx < 0:
        return None
    body_start, body_end = _function_body_range(lines, header_idx)
    body_text = "\n".join(lines[body_start:body_end])
    for pat in _INLINE_AUTH_PATTERNS:
        m = pat.search(body_text)
        if m:
            return m.group(0)[:80]
    return None


def _function_is_access_gated(
    lines: list[str], line_idx: int
) -> Optional[str]:
    """Either a guard modifier or an inline auth check.

    Wrapper used by detectors that want a single "is this function
    behind any access boundary?" answer.
    """
    mod = _function_has_guard_modifier(lines, line_idx)
    if mod:
        return f"modifier:{mod}"
    inline = _function_has_inline_auth(lines, line_idx)
    if inline:
        return f"inline_check:{inline.split('(', 1)[0]}".strip()
    return None


# Contract-level access-control inheritance. Used purely to attach context to
# findings so a reviewer can tell at a glance whether the contract sits on a
# known auth base. Does NOT suppress on its own — inheritance alone is not
# enough; per-function gating still has to be proven.
_KNOWN_ACCESS_CONTROL_BASES = frozenset({
    "ownable", "ownableupgradeable", "ownable2step", "ownable2stepupgradeable",
    "accesscontrol", "accesscontrolupgradeable",
    "accesscontrolenumerable", "accesscontroldefaultadminrules",
    "auth", "authmanaged", "authority",
    "uupsupgradeable", "uupsupgradeablebase",
    "permissions", "rolescontrol",
})

_INHERIT_RE = re.compile(
    r"^\s*(?:abstract\s+)?contract\s+\w+\s+is\s+([^{]+)\{",
)


def _contract_inheritance_bases(source: str) -> list[str]:
    """Return the lower-cased base contract names declared on the file."""
    bases: list[str] = []
    for m in _INHERIT_RE.finditer(source):
        for raw in m.group(1).split(","):
            name = re.sub(r"\(.*\)", "", raw).strip()
            if name:
                bases.append(name.lower())
    return bases


def _file_has_known_access_control_base(source: str) -> Optional[str]:
    for base in _contract_inheritance_bases(source):
        if base in _KNOWN_ACCESS_CONTROL_BASES:
            return base
    return None


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-001: tx.origin == msg.sender bypass
# ─────────────────────────────────────────────────────────────────────────────
# Pre-7702: tx.origin == msg.sender guaranteed the immediate caller was an
# EOA without code. Protocols used this to block contract callers (anti-flash-
# loan, anti-reentrancy). With 7702, an EOA can delegate to code that runs
# during the same tx, so tx.origin == msg.sender passes even when msg.sender
# is executing arbitrary contract logic.
#
# Real usage: OpenZeppelin Address.isContract(), Uniswap V2 Router, Aave
# flashloan guards, countless modifier onlyEOA patterns.

_TX_ORIGIN_EOA_RE = re.compile(
    r"(tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin)",
)
_ONLY_EOA_MODIFIER_RE = re.compile(
    r"modifier\s+(onlyEOA|noContract|isEOA|notContract)\s*\(",
)
_REQUIRE_TX_ORIGIN_RE = re.compile(
    r"require\s*\(\s*(tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin)",
)

# Variable-flow tracking for AA7702-001. The cheap regex catches the literal
# pattern `tx.origin == msg.sender`, but real production code routinely does:
#
#     address initiator = tx.origin;
#     address caller    = msg.sender;
#     require(initiator == caller, "not EOA");
#
# The semantics are identical; the regex misses it. The helpers below scan a
# single function body, build a local alias map (local_var -> "tx.origin" /
# "msg.sender"), and report any `==`/`!=` comparison that resolves to a
# tx.origin/msg.sender pair on either side.
_LOCAL_ASSIGN_TX_ORIGIN_RE = re.compile(
    r"\b(address|uint160|bytes20)\s+(\w+)\s*=\s*tx\.origin\b",
)
_LOCAL_ASSIGN_MSG_SENDER_RE = re.compile(
    r"\b(address|uint160|bytes20)\s+(\w+)\s*=\s*msg\.sender\b",
)
# Reassignments / non-declared writes (e.g. `initiator = tx.origin;`)
_REASSIGN_TX_ORIGIN_RE = re.compile(r"\b(\w+)\s*=\s*tx\.origin\b")
_REASSIGN_MSG_SENDER_RE = re.compile(r"\b(\w+)\s*=\s*msg\.sender\b")
_COMPARE_RE = re.compile(
    r"(tx\.origin|msg\.sender|\b[A-Za-z_]\w*)\s*(==|!=)\s*"
    r"(tx\.origin|msg\.sender|\b[A-Za-z_]\w*)"
)


def _function_body_range(lines: list[str], header_idx: int) -> tuple[int, int]:
    """Return (start_inclusive, end_exclusive) of the function body.

    Walks forward from ``header_idx`` to find the first ``{`` (start), then
    matches braces to find the closing ``}`` (end). The opening-brace line is
    INCLUDED in the range so single-line `function f() { body; }` bodies are
    not silently dropped. Falls back to a 60-line window if matching fails —
    function bodies that large are unusual but the fallback keeps the
    analyzer permissive instead of silent.
    """
    depth = 0
    body_start = -1
    for j in range(header_idx, min(header_idx + 30, len(lines))):
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                if body_start < 0:
                    body_start = j
            elif ch == "}":
                depth -= 1
                if depth == 0 and body_start >= 0:
                    return (body_start, j + 1)
    if body_start < 0:
        return (header_idx + 1, min(header_idx + 60, len(lines)))
    return (body_start, min(body_start + 200, len(lines)))


def _state_aliases_for_origin_sender(source: str) -> dict[str, str]:
    """Scan the whole source for state-variable assignments from
    ``tx.origin`` / ``msg.sender`` and return the alias map.

    Picks up patterns like ``initiator = tx.origin;`` and
    ``lastSender = msg.sender;`` regardless of which function they sit in,
    so a later comparison in a *different* function can resolve the pair.

    The map is built per-file, not per-contract, which is conservative
    but fine: aliases are a hint, not a security guarantee, and the
    consumer also checks the compared-to side has a tx.origin /
    msg.sender resolution before firing.
    """
    aliases: dict[str, str] = {}
    cleaned = _strip_comments(source)
    for line in cleaned.splitlines():
        m = _REASSIGN_TX_ORIGIN_RE.search(line)
        if m and m.group(1) not in {"tx", "msg"}:
            aliases[m.group(1)] = "tx.origin"
        m2 = _REASSIGN_MSG_SENDER_RE.search(line)
        if m2 and m2.group(1) not in {"tx", "msg"}:
            aliases[m2.group(1)] = "msg.sender"
    return aliases


def _detect_aliased_tx_origin_compare(
    lines: list[str], body_start: int, body_end: int
) -> tuple[bool, int]:
    """Return (matched, line_index) for an aliased tx.origin==msg.sender.

    Resolves local aliases first then scans comparisons. Returns the line
    index of the comparison so callers can attach a precise location.
    """
    alias: dict[str, str] = {}
    body = lines[body_start:body_end]
    for raw in body:
        line = re.sub(r"//[^\n]*", "", raw)
        m = _LOCAL_ASSIGN_TX_ORIGIN_RE.search(line)
        if m:
            alias[m.group(2)] = "tx.origin"
            continue
        m = _LOCAL_ASSIGN_MSG_SENDER_RE.search(line)
        if m:
            alias[m.group(2)] = "msg.sender"
            continue
        m2 = _REASSIGN_TX_ORIGIN_RE.search(line)
        if m2 and m2.group(1) not in {"tx", "msg"}:
            alias[m2.group(1)] = "tx.origin"
        m3 = _REASSIGN_MSG_SENDER_RE.search(line)
        if m3 and m3.group(1) not in {"tx", "msg"}:
            alias[m3.group(1)] = "msg.sender"

    for offset, raw in enumerate(body):
        line = re.sub(r"//[^\n]*", "", raw)
        # Skip the literal-pattern case — the direct regex catches it.
        if _TX_ORIGIN_EOA_RE.search(line):
            continue
        for cm in _COMPARE_RE.finditer(line):
            lhs, _op, rhs = cm.group(1), cm.group(2), cm.group(3)
            lhs_resolved = alias.get(lhs, lhs)
            rhs_resolved = alias.get(rhs, rhs)
            if {lhs_resolved, rhs_resolved} == {"tx.origin", "msg.sender"}:
                return (True, body_start + offset)
    return (False, -1)


def _is_aa_infrastructure_file(source: str) -> bool:
    """File whose contracts are AA infrastructure (EntryPoint, StakeManager,
    NonceManager, Bundler, Aggregator, Paymaster), or a pure-library file.

    These contracts validate userOps and book account state — they are not
    themselves the EOA-vs-delegated-EOA boundary that AA7702-001 / 002 are
    meant to flag. tx.origin / code.length appearing inside them is part of
    their service, not a guard developers control.
    """
    if re.search(
        r"\bcontract\s+\w*(EntryPoint|StakeManager|NonceManager|Bundler|"
        r"Aggregator|Paymaster)\b",
        source,
    ):
        return True
    # Pure-library file: `library Foo { ... }` with no concrete contract.
    if (
        re.search(r"^\s*library\s+\w+", source, re.M)
        and not re.search(r"^\s*contract\s+\w+", source, re.M)
    ):
        return True
    return False


def detect_tx_origin_eoa_bypass(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []
    if _is_aa_infrastructure_file(source):
        return findings
    lines = source.splitlines()
    seen_fns: set[str] = set()

    for i, line in enumerate(lines):
        m = _TX_ORIGIN_EOA_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue
        # Skip if the enclosing function is access-controlled. The tx.origin
        # check is then defence-in-depth on a function the caller doesn't
        # control, not the primary security boundary.
        if _function_is_access_gated(lines, i):
            continue
        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)

        findings.append(EIP7702Finding(
            check_id="AA7702-001",
            title=f"EIP-7702 breaks tx.origin==msg.sender EOA check in {fn_name}()",
            severity="CRITICAL",
            description=(
                f"`tx.origin == msg.sender` in `{fn_name}()` was used to ensure the "
                f"caller is a plain EOA without code. After EIP-7702 (Pectra, May 2025), "
                f"EOAs can delegate to arbitrary contract code via SET_CODE_TX_TYPE. "
                f"A delegated EOA passes this check while executing complex logic "
                f"including flash loans, reentrancy, and callback attacks. "
                f"This breaks anti-bot, anti-flash-loan, and anti-contract guards."
            ),
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-284",
            recommendation=(
                "Remove `tx.origin == msg.sender` guard entirely — it no longer "
                "provides any security guarantee post-EIP-7702. For flash loan "
                "protection, use reentrancy guards (checks-effects-interactions + "
                "ReentrancyGuard). For bot protection, use commit-reveal or "
                "time-weighted mechanisms."
            ),
            confidence=0.95,
        ))

    # Variable-flow pass: catch the aliased equivalent
    #     address a = tx.origin; address b = msg.sender; require(a == b);
    # The literal-pattern regex above misses this completely. Real production
    # code routinely stores tx.origin / msg.sender in locals before the check.
    fn_header_re = re.compile(r"^\s*function\s+(\w+)\s*\(")
    for i, line in enumerate(lines):
        fm = fn_header_re.match(line)
        if not fm:
            continue
        fn_name = fm.group(1)
        if fn_name in seen_fns:
            continue
        if _function_is_access_gated(lines, i + 1):
            continue
        body_start, body_end = _function_body_range(lines, i)
        matched, hit_line = _detect_aliased_tx_origin_compare(
            lines, body_start, body_end
        )
        if not matched:
            continue
        seen_fns.add(fn_name)
        findings.append(EIP7702Finding(
            check_id="AA7702-001",
            title=(
                f"EIP-7702 breaks aliased tx.origin==msg.sender check in "
                f"{fn_name}()"
            ),
            severity="CRITICAL",
            description=(
                f"`{fn_name}()` compares two local variables that hold "
                f"`tx.origin` and `msg.sender` respectively. The semantics "
                f"are identical to a direct `tx.origin == msg.sender` check "
                f"and break the same way under EIP-7702: a delegated EOA "
                f"passes the check while executing arbitrary contract code."
            ),
            location=f"{fn_name}():L{hit_line + 1}",
            cwe="CWE-284",
            recommendation=(
                "Drop the alias-equality guard — it provides no EOA "
                "guarantee post-EIP-7702. Use access-control lists or "
                "EIP-712 signed approvals if you need to gate by identity."
            ),
            confidence=0.85,
            semantic_context={
                "analysis": "intra_function_alias_flow",
                "alias_source": "local_variable_assignment",
            },
        ))

    # Cross-function state-variable flow. One function stores tx.origin
    # (or msg.sender) into a state variable; another function compares the
    # same state variable against the other special value. The two
    # functions can be far apart in the file and the intra-function pass
    # above will never see them together.
    state_alias = _state_aliases_for_origin_sender(source)
    if state_alias:
        for i, line in enumerate(lines):
            fm = fn_header_re.match(line)
            if not fm:
                continue
            fn_name = fm.group(1)
            if fn_name in seen_fns:
                continue
            if _function_is_access_gated(lines, i + 1):
                continue
            body_start, body_end = _function_body_range(lines, i)
            hit = -1
            for offset, raw in enumerate(lines[body_start:body_end]):
                line_clean = re.sub(r"//[^\n]*", "", raw)
                if _TX_ORIGIN_EOA_RE.search(line_clean):
                    continue
                for cm in _COMPARE_RE.finditer(line_clean):
                    lhs, _op, rhs = cm.group(1), cm.group(2), cm.group(3)
                    lhs_r = state_alias.get(lhs, lhs)
                    rhs_r = state_alias.get(rhs, rhs)
                    if {lhs_r, rhs_r} == {"tx.origin", "msg.sender"}:
                        hit = body_start + offset
                        break
                if hit >= 0:
                    break
            if hit < 0:
                continue
            seen_fns.add(fn_name)
            findings.append(EIP7702Finding(
                check_id="AA7702-001",
                title=(
                    f"EIP-7702 breaks cross-function tx.origin==msg.sender "
                    f"check in {fn_name}()"
                ),
                severity="CRITICAL",
                description=(
                    f"`{fn_name}()` compares a state variable (`"
                    f"{', '.join(sorted(state_alias))}` is stored from "
                    f"tx.origin/msg.sender elsewhere in the file) against "
                    f"the current `msg.sender` / `tx.origin`. The check is "
                    f"semantically equivalent to a direct "
                    f"tx.origin==msg.sender comparison and breaks the "
                    f"same way under EIP-7702 — a delegated EOA passes "
                    f"while executing contract logic."
                ),
                location=f"{fn_name}():L{hit + 1}",
                cwe="CWE-284",
                recommendation=(
                    "Do not gate access on stored-EOA equality. Use a "
                    "role-based ACL, an EIP-712 signed approval, or "
                    "commit-reveal — none of which can be bypassed by "
                    "delegated execution."
                ),
                confidence=0.78,
                semantic_context={
                    "analysis": "cross_function_state_alias_flow",
                    "alias_source": "state_variable_assignment",
                    "tracked_aliases": sorted(state_alias.keys()),
                },
            ))

    # Also check for onlyEOA-style modifiers
    for i, line in enumerate(lines):
        m = _ONLY_EOA_MODIFIER_RE.search(line)
        if not m:
            continue
        mod_name = m.group(1)
        if mod_name in seen_fns:
            continue
        seen_fns.add(mod_name)
        findings.append(EIP7702Finding(
            check_id="AA7702-001",
            title=f"EIP-7702 breaks `{mod_name}` modifier assumption",
            severity="CRITICAL",
            description=(
                f"Modifier `{mod_name}` likely checks `tx.origin == msg.sender` "
                f"or `!isContract(msg.sender)` to restrict callers to EOAs. "
                f"Post-EIP-7702, EOAs can execute arbitrary code via delegation, "
                f"making this modifier ineffective as a security boundary."
            ),
            location=f"modifier {mod_name}:L{i+1}",
            cwe="CWE-284",
            recommendation=(
                "Remove the modifier or replace with a mechanism that doesn't "
                "rely on the EOA/contract distinction (e.g., access control lists, "
                "commit-reveal schemes, or EIP-712 signed approvals)."
            ),
            confidence=0.88,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-002: isContract / code.length == 0 assumption broken
# ─────────────────────────────────────────────────────────────────────────────
# Pre-7702: extcodesize(addr) == 0 meant addr is an EOA (or a contract in
# its constructor). With 7702, an EOA's code is the delegation designator
# (0xef0100 ++ address), so extcodesize > 0 for delegated EOAs.
# Conversely, checking code.length == 0 to "ensure EOA" now misclassifies
# delegated EOAs.
#
# Real usage: OpenZeppelin Address.isContract(), ERC-721 _checkOnERC721Received,
# SafeERC20, token receive hooks.

_ISCONTRACT_RE = re.compile(
    r"(\.isContract\s*\(|\.code\.length\s*(==|!=|>|<)\s*0"
    r"|extcodesize\s*\(\s*\w+\s*\)\s*(==|!=|>|<)\s*0"
    r"|codesize\s*:=\s*extcodesize)",
)


def detect_iscontract_bypass(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []
    if _is_aa_infrastructure_file(source):
        return findings
    lines = source.splitlines()
    seen_fns: set[str] = set()

    for i, line in enumerate(lines):
        m = _ISCONTRACT_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue
        # An access-controlled function performing isContract on a known
        # target is checking shape, not auth boundary — drop the alert.
        if _function_is_access_gated(lines, i):
            continue
        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)

        matched = m.group(0).strip()
        findings.append(EIP7702Finding(
            check_id="AA7702-002",
            title=f"EIP-7702 breaks EOA detection via `{matched}` in {fn_name}()",
            severity="HIGH",
            description=(
                f"`{matched}` in `{fn_name}()` assumes code.length distinguishes "
                f"EOAs from contracts. After EIP-7702, an EOA delegating to a "
                f"contract has a non-zero code field (the 23-byte delegation "
                f"designator 0xef0100||address). This breaks: (1) token receive "
                f"hook checks (ERC-721/1155 safeTransfer), (2) flash loan guards, "
                f"(3) airdrop eligibility filters, (4) governance voting weight."
            ),
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-697",
            recommendation=(
                "Do not use code.length or isContract() as a security boundary. "
                "For token receive hooks, accept that EOAs can now have code and "
                "handle callbacks accordingly. For access control, use explicit "
                "allowlists or EIP-712 signatures instead."
            ),
            confidence=0.90,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-003: Callback reentrancy via delegated EOA
# ─────────────────────────────────────────────────────────────────────────────
# Pre-7702: Sending ETH to an EOA via transfer/send was safe from reentrancy
# because EOAs couldn't execute code on receive. With 7702, a delegated EOA
# can have a receive() or fallback() function that re-enters the caller.
#
# This is subtle: a contract might use .transfer() (2300 gas stipend) thinking
# it's safe because "it's an EOA." But delegated EOAs can receive callbacks
# and the 2300 gas limit was already insufficient for many operations.

_ETH_SEND_RE = re.compile(
    r"(\.transfer\s*\(|\.send\s*\(|\.call\s*\{.*value\s*:)",
)
_EOA_CONTEXT_RE = re.compile(
    r"(eoa|user|owner|recipient|sender|beneficiary|payee|to)\b",
    re.IGNORECASE,
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(nonReentrant|ReentrancyGuard|_status|_locked|noReentrant)",
)


def detect_callback_reentrancy(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []
    lines = source.splitlines()
    seen_fns: set[str] = set()

    for i, line in enumerate(lines):
        m = _ETH_SEND_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue
        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue

        # Check if there's a reentrancy guard on the function
        fn_start = i
        for j in range(i, max(i - 20, -1), -1):
            if re.match(r"^\s*function\s+", lines[j]):
                fn_start = j
                break
        fn_header = " ".join(lines[fn_start:fn_start + 3])
        if _REENTRANCY_GUARD_RE.search(fn_header):
            continue
        # Internal-only functions (no `public`/`external` keyword in the
        # signature) are not directly attacker-reachable. They only fire
        # AA7702-003 when their caller is itself an unguarded public
        # surface — and that caller is what the analyzer should flag
        # instead. Drop the alert here. (Safe.handlePayment is `private`
        # and only invoked from `execTransaction`, which already gates
        # the call chain.)
        if not re.search(r"\b(public|external)\b", fn_header):
            continue
        # Access-control gating turns the reentrancy concern into a
        # self-harm scenario: only the owner / role-holder can call,
        # so a delegated EOA reentering during the callback is the
        # owner attacking themselves. Drop the alert.
        if _function_is_access_gated(lines, i):
            continue

        # Check if target is assumed to be an EOA
        context_window = "\n".join(lines[max(0, i - 5):i + 3])
        has_eoa_context = _EOA_CONTEXT_RE.search(context_window)

        # If function contains isContract check or tx.origin check,
        # it's trying to ensure EOA — which is now broken
        has_eoa_guard = bool(re.search(
            r"(isContract|tx\.origin|code\.length)", context_window
        ))

        if has_eoa_guard or has_eoa_context:
            seen_fns.add(fn_name)
            severity = "HIGH" if has_eoa_guard else "MEDIUM"
            findings.append(EIP7702Finding(
                check_id="AA7702-003",
                title=f"EIP-7702 enables callback reentrancy via delegated EOA in {fn_name}()",
                severity=severity,
                description=(
                    f"`{fn_name}()` sends ETH to an address assumed to be an EOA "
                    f"(based on {'EOA guard check' if has_eoa_guard else 'variable naming'}). "
                    f"Pre-EIP-7702, ETH transfers to EOAs were safe from reentrancy. "
                    f"Post-7702, a delegated EOA has a receive()/fallback() that can "
                    f"execute arbitrary code, including re-entering `{fn_name}()`. "
                    f"The .transfer() 2300 gas stipend does NOT protect against this — "
                    f"delegation code runs in a separate context."
                ),
                location=f"{fn_name}():L{i+1}",
                cwe="CWE-841",
                recommendation=(
                    "Add ReentrancyGuard (nonReentrant modifier) to any function "
                    "that sends ETH. Follow checks-effects-interactions pattern: "
                    "update all state BEFORE the external call. Do not rely on "
                    "the EOA/contract distinction for reentrancy safety."
                ),
                confidence=0.75 if has_eoa_guard else 0.60,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-004: Cross-chain delegation replay
# ─────────────────────────────────────────────────────────────────────────────
# EIP-7702 authorization tuples include chain_id. If chain_id = 0, the
# authorization is valid on ALL chains. A contract that processes or stores
# delegation info without verifying chain_id enables cross-chain replay.

_CHAIN_ID_ZERO_RE = re.compile(
    r"(chainId\s*[=:]\s*0|chain_id\s*[=:]\s*0|chainid\s*==\s*0)",
    re.IGNORECASE,
)
_DELEGATION_RE = re.compile(
    r"(\bauthoriz(?:ation|e|ed|es|ing)?\b|"
    r"\bdelegat(?:e|ed|es|ing|ion|ions|or|ors)?\b|"
    r"setCode|0x04|SET_CODE|eip7702|eip_7702|7702)",
    re.IGNORECASE,
)
_CHAIN_ID_CHECK_RE = re.compile(
    r"(block\.chainid|chainId\s*!=\s*0|chainId\s*>\s*0|require.*chainId)",
    re.IGNORECASE,
)


def detect_cross_chain_replay(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_delegation = _DELEGATION_RE.search(source)
    if not has_delegation:
        return findings

    lines = source.splitlines()
    seen_fns: set[str] = set()

    # Check for chain_id = 0 patterns
    for i, line in enumerate(lines):
        m = _CHAIN_ID_ZERO_RE.search(line)
        if not m:
            continue
        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)
        findings.append(EIP7702Finding(
            check_id="AA7702-004",
            title=f"EIP-7702 cross-chain delegation replay: chainId=0 in {fn_name}()",
            severity="HIGH",
            description=(
                f"`{fn_name}()` uses chainId=0 in a delegation/authorization context. "
                f"EIP-7702 authorizations with chain_id=0 are valid on ALL EVM chains. "
                f"An attacker can capture a user's authorization on one chain and replay "
                f"it on another, delegating the victim's EOA to an attacker-controlled "
                f"contract on the replay chain."
            ),
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-294",
            recommendation=(
                "Always use `block.chainid` instead of 0 for chain_id in "
                "authorization tuples. Validate that received authorizations "
                "match `block.chainid` or reject chain_id=0 authorizations "
                "if cross-chain operation is not intended."
            ),
            confidence=0.85,
        ))

    # ERC-4337 accounts bind chain_id transitively through the EntryPoint's
    # userOpHash (the EntryPoint includes block.chainid in the typehash
    # before calling validateUserOp). If the contract takes `userOpHash`
    # in a validate-style entrypoint, the chain_id check is satisfied by
    # the protocol — surface AA7702-004 only when no userOpHash binding
    # is observed AND no direct chain_id check is present.
    binds_chain_via_userophash = bool(re.search(
        r"validateUserOp\s*\([^)]*userOpHash|validatePaymasterUserOp\s*\([^)]*userOpHash",
        source,
    )) or bool(re.search(
        r"\buserOpHash\b.*\b(_validateSignature|isValidSignature|ECDSA\.recover|"
        r"hashTypedData|_hashTypedData|hashSignedData)\b",
        source,
        re.S,
    ))

    # Check if delegation code exists but no chain_id validation
    if (
        has_delegation
        and not _CHAIN_ID_CHECK_RE.search(source)
        and not binds_chain_via_userophash
        and not findings
    ):
        findings.append(EIP7702Finding(
            check_id="AA7702-004",
            title="EIP-7702 delegation without chain_id validation",
            severity="MEDIUM",
            description=(
                "Contract contains EIP-7702 delegation/authorization logic but "
                "does not validate `block.chainid`. Without chain_id checks, "
                "authorizations may be replayed across chains if chain_id=0 is used."
            ),
            location="contract-level",
            cwe="CWE-294",
            recommendation=(
                "Add `require(auth.chainId == block.chainid || auth.chainId == 0)` "
                "and clearly document whether cross-chain authorizations are intended. "
                "If not, reject chain_id=0."
            ),
            confidence=0.65,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-005: Missing delegation revocation
# ─────────────────────────────────────────────────────────────────────────────
# EIP-7702 lets EOAs set their code via authorization. To revoke, the EOA
# must send a new 7702 tx delegating to address(0) or a no-op contract.
# If a delegation-aware contract stores delegation state but has no
# revocation path, users are permanently locked into a delegation.

_SET_DELEGATION_RE = re.compile(
    r"(setDelegat|updateDelegation|registerDelegation|storeDelegation|addDelegation"
    r"|setCode|applyAuthorization)",
    re.IGNORECASE,
)
_REVOKE_RE = re.compile(
    r"(revoke|remove|clear|reset|unset|cancel|disable).*(?:delegat|auth)",
    re.IGNORECASE,
)


def detect_missing_revocation(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_set = _SET_DELEGATION_RE.search(source)
    if not has_set:
        return findings
    if (
        has_set.group(0).lower().startswith("setdelegat")
        and re.search(r"\bendpoint\s*\.\s*setDelegate\s*\(", source)
        and not re.search(r"\b(delegates|delegations|delegationTarget)\b\s*(?:\[|=|;)", source)
    ):
        return findings

    has_revoke = _REVOKE_RE.search(source)

    if not has_revoke:
        findings.append(EIP7702Finding(
            check_id="AA7702-005",
            title="EIP-7702 delegation without revocation mechanism",
            severity="MEDIUM",
            description=(
                "Contract stores or processes EIP-7702 delegation state "
                f"(matched: `{has_set.group(0)}`) but contains no function to "
                "revoke or clear the delegation. Users cannot undo a delegation "
                "through this contract, potentially locking them into a malicious "
                "or outdated delegation target. While the EOA owner can always "
                "send a new 7702 tx to change delegation on-chain, the contract's "
                "stored state becomes stale."
            ),
            location="contract-level",
            cwe="CWE-269",
            recommendation=(
                "Add a `revokeDelegation()` function that clears stored delegation "
                "state. For maximum safety, include an `emergencyRevoke()` callable "
                "by the delegating EOA with no restrictions."
            ),
            confidence=0.72,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-006: delegatecall from delegation target
# ─────────────────────────────────────────────────────────────────────────────
# When an EOA delegates to a contract via EIP-7702, that contract's code
# runs in the EOA's context. If the delegation target uses delegatecall,
# it introduces a second level of context confusion: the delegatecall
# target's code runs in the EOA's context with the EOA's storage, but
# msg.sender becomes the delegation target's address.

_DELEGATECALL_RE = re.compile(
    r"(\.delegatecall\s*\(|delegatecall\s*\()",
)
_EIP7702_TARGET_RE = re.compile(
    r"(7702|setCode|executeAs|delegatedExec|EIP7702|EIP-7702"
    r"|AccountDelegation|DelegationTarget|DelegationStorage|DelegateAccount|SmartAccount"
    r"|contract\s+\w*(?:Delegation|Delegate)\w*)",
    re.IGNORECASE,
)
# Contracts that reference "delegation" via imports but are NOT delegation
# targets — they're infrastructure (enforcers, modules, factories, etc.)
_NOT_DELEGATION_TARGET_RE = re.compile(
    # Names that are infrastructure for AA / 7702 but are not themselves
    # delegation targets — EntryPoint sits at the boundary, Paymaster /
    # Bundler / StakeManager are service contracts, etc.
    r"contract\s+\w*("
    r"Enforcer|Module|Factory|Manager|Registry|Resolver|Hook|Guard|"
    r"Paymaster|Bundler|EntryPoint|StakeManager|NonceManager|"
    r"Aggregator|Initializable)\b",
)


def _is_delegation_target(source: str) -> bool:
    """Check if source is a delegation target (not just references delegation)."""
    if not _EIP7702_TARGET_RE.search(source):
        return False
    if _NOT_DELEGATION_TARGET_RE.search(source):
        return False
    return True


# ── Universal FP-suppression primitives (Stage 2) ──────────────────────────
# These key on code STRUCTURE/SEMANTICS, never on repo or contract names, so
# they generalize to any Solidity project instead of overfitting a test set.

def _is_interface_file(source: str) -> bool:
    """True if the file is interface-only (no implementation → cannot hold a
    runtime vuln). Conservative: any concrete contract/library ⇒ not interface."""
    s = _strip_comments(source)
    if re.search(r"\b(contract|library)\s+\w+", s):
        return False  # has a concrete implementation type
    if not re.search(r"\binterface\s+\w+", s):
        return False  # not an interface declaration at all
    flat = re.sub(r"\s+", " ", s)
    # any function with an actual body { } (multi-line safe; no ';' before '{')
    if re.search(r"\bfunction\b[^;{}]*\)[^;{}]*\{", flat):
        return False
    return True


_SIG_VERIFY_RE = re.compile(
    r"(ecrecover|isValidSignature|_validateSignature|SignatureChecker|recoverSigner|"
    r"tryRecover|signature|_verify|\bverify\w*\(|\brecover\b)",
    re.I,
)
_SIG_VERIFY_STRICT_RE = re.compile(
    r"(ecrecover\s*\(|ECDSA\.recover\s*\(|isValidSignature\s*\(|"
    r"SignatureChecker|recoverSigner|tryRecover|_validateSignature|"
    r"_verify\s*\(|\bverify\w*\()",
    re.I,
)
_CHAIN_BIND_RE = re.compile(
    r"(block\.chainid|_domainSeparator|DOMAIN_SEPARATOR|domainSeparator|EIP712|_hashTypedData|"
    r"keccak256\([^)]*chainid)",
    re.I,
)
_ENTRYPOINT_RE = re.compile(
    r"(IEntryPoint|entryPoint|EntryPoint|ERC4337|ERC-4337|handleOps|UserOperation|validateUserOp)"
)
_ERC7201_RE = re.compile(
    # ERC-7201 annotations / formula, PLUS hand-rolled namespaced-storage accessors
    # (assembly `$.slot := <const>` and `_getXStorage()` patterns) used by Ithaca,
    # Solady, OZ etc. — these structurally prevent storage collisions.
    # Also covers keccak256("eip7201:...") formula and bytes32 constant slot declarations.
    r"(erc7201|eip7201|custom:storage-location|abi\.encode\(uint256\(keccak256"
    r"|keccak256\(['\"]eip7201:"
    r"|\.slot\s*:=|function\s+_get\w*[Ss]torage\s*\(|StorageSlot\."
    r"|_STORAGE_(SLOT|LOCATION)|bytes32\s+private\s+constant\s+\w+_SLOT)",
    re.I,
)
_EXTERNAL_FUNCTION_RE = re.compile(
    r"\bfunction\s+(\w+)\s*\([^;{}]*\)\s*([^;{}]*)\{",
    re.I | re.S,
)
_ACCESS_GUARD_RE = re.compile(
    r"\b(onlyOwner|onlyRole|onlyAdmin|onlyEntryPoint|onlySelf|requiresAuth|"
    r"requireAuth|auth|nonReentrant)\b|require\s*\([^;{]*(?:msg\.sender\s*==|"
    r"hasRole\s*\(|owner\s*\(|_owner|entryPoint|ENTRY_POINT)",
    re.I | re.S,
)
_SEMANTIC_REENTRANCY_GUARD_RE = re.compile(
    r"\b(nonReentrant|ReentrancyGuard)\b|_status\s*==\s*_NOT_ENTERED|"
    r"_entered\s*=\s*true",
    re.I,
)
_CONTRACT_BIND_RE = re.compile(
    r"\b(address\s*\(\s*this\s*\)|verifyingContract|_domainSeparatorV4|"
    r"DOMAIN_SEPARATOR|domainSeparator)",
    re.I,
)
_NONCE_BIND_RE = re.compile(
    r"\b(nonce|nonces|useNonce|_useNonce|getNonce)\b",
    re.I,
)
_ERC1271_RE = re.compile(
    r"\b(isValidSignature|SignatureChecker|ERC1271|IERC1271)\b",
    re.I,
)
_ERC6492_RE = re.compile(
    r"\b(ERC6492|6492|isValidERC6492Signature|prepareSignature|factoryCalldata)\b",
    re.I,
)
_USEROP_HASH_RE = re.compile(
    r"\b(userOpHash|getUserOpHash|hashUserOp|_hashUserOp)\b",
    re.I,
)
_ENTRYPOINT_BIND_RE = re.compile(
    r"\b(entryPoint|ENTRY_POINT|IEntryPoint|msg\.sender\s*==\s*[^;]*entryPoint|"
    r"onlyEntryPoint|fromEntryPoint)\b",
    re.I,
)
_VALIDATE_USEROP_RE = re.compile(r"\bvalidateUserOp\s*\(", re.I)
_SOURCE_PATTERNS = {
    "calldata": re.compile(r"\b(calldata|msg\.data|abi\.decode)\b", re.I),
    "signature": re.compile(r"\b(signature|sig|r\s*,\s*s|v\s*,\s*r\s*,\s*s)\b", re.I),
    "userop": re.compile(r"\b(UserOperation|PackedUserOperation|userOp|userOpHash)\b", re.I),
    "authorization": re.compile(r"\b(authorization|authTuple|authorizationList|7702)\b", re.I),
}
_SINK_PATTERNS = {
    "execute": re.compile(r"\bexecute(?:Batch)?\s*\(|\.call\s*\(", re.I),
    "delegatecall": re.compile(r"\bdelegatecall\s*\(", re.I),
    "asset_transfer": re.compile(
        r"\b(transfer|transferFrom|safeTransferFrom|approve|setApprovalForAll)\s*\(",
        re.I,
    ),
    "module_or_validator": re.compile(r"\b(installModule|setValidator|setSigner)\s*\(", re.I),
    "upgrade": re.compile(r"\b(upgradeTo|setImplementation)\s*\(", re.I),
    "state_write": re.compile(r"\b(sstore|assembly\s*\{|initialize|setOwner|set[A-Z]\w*)\b", re.I),
}


def _semantic_context_for_source(content: str, analysis: str = "regex") -> dict:
    clean = _strip_comments(content)
    functions = _EXTERNAL_FUNCTION_RE.findall(clean)
    external_entrypoints = [
        name for name, attrs in functions
        if re.search(r"\b(public|external)\b", attrs)
    ]
    guarded_entrypoints = [
        name for name, attrs in functions
        if re.search(r"\bonly\w+|requiresAuth|requireAuth|auth|nonReentrant\b", attrs, re.I)
    ]
    sources = sorted(name for name, pattern in _SOURCE_PATTERNS.items() if pattern.search(clean))
    sinks = sorted(name for name, pattern in _SINK_PATTERNS.items() if pattern.search(clean))
    binds_chain = bool(_CHAIN_BIND_RE.search(clean))
    binds_contract = bool(_CONTRACT_BIND_RE.search(clean))
    binds_nonce = bool(_NONCE_BIND_RE.search(clean))
    uses_erc1271 = bool(_ERC1271_RE.search(clean))
    uses_erc6492 = bool(_ERC6492_RE.search(clean))
    binds_userop_hash = bool(_USEROP_HASH_RE.search(clean))
    binds_entrypoint = bool(_ENTRYPOINT_BIND_RE.search(clean))
    has_validate_userop = bool(_VALIDATE_USEROP_RE.search(clean))
    verifies_signature = bool(_SIG_VERIFY_STRICT_RE.search(clean))
    uses_entrypoint = bool(_ENTRYPOINT_RE.search(clean))
    uses_erc7201 = bool(_ERC7201_RE.search(clean))
    has_access_guard = bool(_ACCESS_GUARD_RE.search(clean))
    has_reentrancy_guard = bool(_SEMANTIC_REENTRANCY_GUARD_RE.search(clean))
    complete_signature_model = bool(
        verifies_signature
        and binds_chain
        and binds_contract
        and binds_nonce
        and uses_erc1271
    )
    signature_missing = []
    if verifies_signature:
        if not binds_chain:
            signature_missing.append("chain_id")
        if not binds_contract:
            signature_missing.append("verifying_contract")
        if not binds_nonce:
            signature_missing.append("nonce")
        if not uses_erc1271:
            signature_missing.append("erc1271_fallback")

    userop_missing = []
    if has_validate_userop or "userop" in sources:
        if not binds_userop_hash:
            userop_missing.append("userOpHash")
        if not binds_nonce:
            userop_missing.append("nonce")
        if not binds_entrypoint:
            userop_missing.append("entryPoint")
        if not verifies_signature:
            userop_missing.append("signature_verification")

    signature_model = {
        "verifies_signature": verifies_signature,
        "binds_chain_id": binds_chain,
        "binds_contract": binds_contract,
        "binds_nonce": binds_nonce,
        "uses_erc1271": uses_erc1271,
        "uses_erc6492": uses_erc6492,
        "complete": complete_signature_model,
        "missing": signature_missing,
    }
    userop_model = {
        "has_validate_userop": has_validate_userop,
        "uses_userop": "userop" in sources,
        "binds_userop_hash": binds_userop_hash,
        "binds_nonce": binds_nonce,
        "binds_entrypoint": binds_entrypoint,
        "verifies_signature": verifies_signature,
        "missing": userop_missing,
    }
    return {
        "analysis": analysis,
        "external_entrypoints": len(external_entrypoints),
        "guarded_entrypoints": len(guarded_entrypoints),
        "has_access_guard": has_access_guard,
        "has_reentrancy_guard": has_reentrancy_guard,
        "sources": sources,
        "sinks": sinks,
        "verifies_signature": verifies_signature,
        "binds_chain_id": binds_chain,
        "binds_contract": binds_contract,
        "binds_nonce": binds_nonce,
        "uses_erc1271": uses_erc1271,
        "uses_erc6492": uses_erc6492,
        "binds_userop_hash": binds_userop_hash,
        "binds_entrypoint": binds_entrypoint,
        "has_validate_userop": has_validate_userop,
        "uses_entrypoint": uses_entrypoint,
        "uses_erc7201": uses_erc7201,
        "complete_signature_model": complete_signature_model,
        "signature_model": signature_model,
        "userop_model": userop_model,
    }


def _summarize_semantics(per_file: dict) -> dict:
    all_sources: set[str] = set()
    all_sinks: set[str] = set()
    complete_signature_files = 0
    guarded_files = 0
    for sem in per_file.values():
        all_sources.update(sem.get("sources") or [])
        all_sinks.update(sem.get("sinks") or [])
        if sem.get("complete_signature_model"):
            complete_signature_files += 1
        if sem.get("has_access_guard"):
            guarded_files += 1
    return {
        "files": len(per_file),
        "sources": sorted(all_sources),
        "sinks": sorted(all_sinks),
        "complete_signature_files": complete_signature_files,
        "guarded_files": guarded_files,
    }


def _ast_project_context(sources: dict) -> dict:
    """Optional solc-AST facts for --deep mode. Best-effort: unresolved imports
    or missing solc simply leave the default regex path in charge."""
    try:
        try:
            from . import ast_utils
        except ImportError:
            import ast_utils  # type: ignore
    except Exception:
        return {"ast_enabled": False, "ast_files": 0, "ast_interface_files": set()}

    interface_files: set[str] = set()
    fact_files: set[str] = set()
    uses_erc7201 = False
    verifies_signatures = False
    files_with_ast = 0
    for fname, content in sources.items():
        try:
            facts = ast_utils.extract_facts(content)
        except Exception:
            facts = []
        if not facts:
            continue
        files_with_ast += 1
        fact_files.add(fname)
        if all(f.kind == "interface" for f in facts):
            interface_files.add(fname)
        uses_erc7201 = uses_erc7201 or any(f.uses_erc7201 for f in facts)
        verifies_signatures = verifies_signatures or any(f.verifies_signatures for f in facts)
    return {
        "ast_enabled": files_with_ast > 0,
        "ast_files": files_with_ast,
        "ast_fact_files": fact_files,
        "ast_interface_files": interface_files,
        "ast_uses_erc7201": uses_erc7201,
        "ast_verifies_signatures": verifies_signatures,
    }


def _semantic_index_project_context(sources: dict) -> dict:
    """Best-effort project semantic index for deep mode.

    Unlike the solc AST bridge, this works without external compiler setup and
    captures cross-contract facts: inheritance, modifiers, internal calls,
    initializers, and proxy-like surfaces.
    """
    try:
        try:
            from .semantic_index import build_semantic_index
        except ImportError:
            from semantic_index import build_semantic_index  # type: ignore
        index = build_semantic_index(sources)
    except Exception:
        return {
            "semantic_index_enabled": False,
            "semantic_index": {},
            "semantic_index_files": set(),
        }
    return {
        "semantic_index_enabled": True,
        "semantic_index": index.to_dict(),
        "semantic_index_files": set(index.by_file.keys()),
        "_semantic_index_obj": index,
    }


def _compiler_model_project_context(sources: dict) -> dict:
    """Compiler-backed project model for deep mode.

    This starts the 10/10 Gate 1 migration: standard JSON facts are attached to
    findings when solc can compile the project, and a labeled fallback is kept
    when it cannot.
    """
    try:
        try:
            from .solidity_project_model import build_project_model
        except ImportError:
            from solidity_project_model import build_project_model  # type: ignore
        model = build_project_model(sources)
    except Exception:
        return {
            "compiler_model_enabled": False,
            "compiler_model": {},
            "compiler_model_by_file": {},
        }

    by_file: dict[str, list[dict]] = {}
    for contract in model.contracts:
        by_file.setdefault(contract.file, []).append(contract.to_dict())
    return {
        "compiler_model_enabled": True,
        "compiler_model": model.to_dict(),
        "compiler_model_by_file": by_file,
    }


def _semantic_ir_project_context(sources: dict) -> dict:
    """Compiler-backed function-flow facts for deep mode."""
    try:
        try:
            from .semantic_ir import build_semantic_ir
        except ImportError:
            from semantic_ir import build_semantic_ir  # type: ignore
        project = build_semantic_ir(sources)
    except Exception:
        return {
            "semantic_ir_enabled": False,
            "semantic_ir": {},
            "semantic_ir_by_file": {},
        }

    by_file: dict[str, list[dict]] = {}
    for function in project.functions:
        by_file.setdefault(function.file, []).append(function.to_dict())
    return {
        "semantic_ir_enabled": project.analysis_depth == "standard_json_ast_ir",
        "semantic_ir": project.to_dict(),
        "semantic_ir_by_file": by_file,
    }


def _semantic_ir_file_summary(functions: list[dict]) -> dict:
    facts_by_kind: dict[str, int] = {}
    for function in functions:
        for key, value in function.items():
            if isinstance(value, list) and key.endswith(("calls", "checks", "writes", "reads", "transfers", "parameters")):
                facts_by_kind[key] = facts_by_kind.get(key, 0) + len(value)
    return {
        "functions": len(functions),
        "facts": sum(facts_by_kind.values()),
        "facts_by_kind": dict(sorted(facts_by_kind.items())),
    }


def _call_graph_project_context_from_ir(semantic_ir: dict) -> dict:
    try:
        try:
            from .call_graph import call_graph_from_ir_functions
        except ImportError:
            from call_graph import call_graph_from_ir_functions  # type: ignore
        graph = call_graph_from_ir_functions(semantic_ir.get("functions") or [])
    except Exception:
        return {
            "call_graph_enabled": False,
            "call_graph": {},
            "call_graph_by_file": {},
        }

    payload = graph.to_dict()
    by_file: dict[str, dict] = {}
    nodes_by_file: dict[str, set[str]] = {}
    for node in payload.get("nodes") or []:
        fname = node.get("file")
        if not fname:
            continue
        nodes_by_file.setdefault(fname, set()).add(node.get("qualified_name", ""))
        by_file.setdefault(fname, {"nodes": [], "edges": [], "unresolved_edges": []})
        by_file[fname]["nodes"].append(node)
    for edge in payload.get("edges") or []:
        source = edge.get("source")
        for fname, node_names in nodes_by_file.items():
            if source in node_names:
                by_file.setdefault(fname, {"nodes": [], "edges": [], "unresolved_edges": []})
                by_file[fname]["edges"].append(edge)
                if edge.get("uncertainty"):
                    by_file[fname]["unresolved_edges"].append(edge)
    for file_payload in by_file.values():
        file_payload["summary"] = {
            "nodes": len(file_payload["nodes"]),
            "edges": len(file_payload["edges"]),
            "unresolved_edges": len(file_payload["unresolved_edges"]),
        }
    return {
        "call_graph_enabled": bool(payload.get("nodes")),
        "call_graph": payload,
        "call_graph_by_file": by_file,
    }


def build_project_context(sources: dict, deep: bool = False) -> dict:
    """Project-wide index built once from every source file. Lets single-file
    checks be gated on facts that live in OTHER files (domain separators,
    EntryPoint usage, ERC-7201 namespacing) — the universal fix for cross-file
    false positives."""
    clean = _strip_comments("\n".join(sources.values()))
    semantic_files = {
        fname: _semantic_context_for_source(content)
        for fname, content in sources.items()
    }
    ctx = {
        "binds_chain_id": bool(_CHAIN_BIND_RE.search(clean)),
        "uses_entrypoint": bool(_ENTRYPOINT_RE.search(clean)),
        "uses_erc7201": bool(_ERC7201_RE.search(clean)),
        "semantic_files": semantic_files,
        "semantic_summary": _summarize_semantics(semantic_files),
        "deep": deep,
    }
    if deep:
        compiler_ctx = _compiler_model_project_context(sources)
        ctx.update(compiler_ctx)
        compiler_model = compiler_ctx.get("compiler_model") or {}
        compiler_by_file = compiler_ctx.get("compiler_model_by_file") or {}
        compiler_depth = compiler_model.get("analysis_depth")
        compiler_summary = compiler_model.get("summary")
        for fname, contracts in compiler_by_file.items():
            if fname not in semantic_files:
                continue
            semantic_files[fname]["compiler_model"] = {
                "analysis_depth": compiler_depth,
                "compiler_status": compiler_model.get("compiler_status"),
                "fallback_reason": compiler_model.get("fallback_reason"),
                "contracts": contracts,
            }
            if compiler_depth == "standard_json_ast":
                semantic_files[fname]["analysis"] = "standard_json_ast"
        if compiler_summary:
            ctx["semantic_summary"]["compiler_model"] = compiler_summary
        ir_ctx = _semantic_ir_project_context(sources)
        ctx.update(ir_ctx)
        semantic_ir = ir_ctx.get("semantic_ir") or {}
        ir_by_file = ir_ctx.get("semantic_ir_by_file") or {}
        for fname, functions in ir_by_file.items():
            if fname not in semantic_files:
                continue
            semantic_files[fname]["semantic_ir"] = {
                "analysis_depth": semantic_ir.get("analysis_depth"),
                "compiler_status": semantic_ir.get("compiler_status"),
                "fallback_reason": semantic_ir.get("fallback_reason"),
                "summary": _semantic_ir_file_summary(functions),
                "functions": functions,
            }
            if semantic_ir.get("analysis_depth") == "standard_json_ast_ir":
                semantic_files[fname]["analysis"] = "standard_json_ast"
        if semantic_ir.get("summary"):
            ctx["semantic_summary"]["semantic_ir"] = semantic_ir["summary"]
        semantic_ir_for_graph = dict(semantic_ir)
        if not semantic_ir_for_graph.get("functions") and ir_by_file:
            semantic_ir_for_graph["functions"] = [
                function
                for functions in ir_by_file.values()
                for function in functions
            ]
        call_graph_ctx = _call_graph_project_context_from_ir(semantic_ir_for_graph)
        ctx.update(call_graph_ctx)
        for fname, graph in (call_graph_ctx.get("call_graph_by_file") or {}).items():
            if fname in semantic_files:
                semantic_files[fname]["call_graph"] = graph
        if call_graph_ctx.get("call_graph", {}).get("summary"):
            ctx["semantic_summary"]["call_graph"] = call_graph_ctx["call_graph"]["summary"]
        ast_ctx = _ast_project_context(sources)
        ctx.update(ast_ctx)
        for fname in ast_ctx.get("ast_fact_files", set()):
            if fname in semantic_files:
                if semantic_files[fname].get("analysis") != "standard_json_ast":
                    semantic_files[fname]["analysis"] = "ast+regex"
        ctx["uses_erc7201"] = bool(ctx.get("uses_erc7201") or ctx.get("ast_uses_erc7201"))
        index_ctx = _semantic_index_project_context(sources)
        ctx.update(index_ctx)
        index = index_ctx.get("_semantic_index_obj")
        if index is not None:
            for fname in index_ctx.get("semantic_index_files", set()):
                if fname not in semantic_files:
                    continue
                previous = semantic_files[fname].get("analysis", "regex")
                if previous != "standard_json_ast" and "semantic_index" not in previous:
                    semantic_files[fname]["analysis"] = f"{previous}+semantic_index"
                semantic_files[fname]["semantic_index"] = index.file_summary(fname)
            ctx["semantic_summary"]["semantic_index"] = index.summary()
        ctx.pop("_semantic_index_obj", None)
    return ctx


def _semantic_path_findings_for_file(
    fname: str, sem: dict, source: str = ""
) -> list["EIP7702Finding"]:
    """Deep-mode semantic path findings for EOA gates hidden in modifiers.

    Regex checks already catch the primitive pattern. These findings attach the
    vulnerable guard to the externally reachable function that inherits or uses
    the modifier, which is the action a reviewer needs.
    """
    index = sem.get("semantic_index") or {}
    findings: list[EIP7702Finding] = []
    seen: set[tuple[str, str]] = set()
    for fn in index.get("functions") or []:
        if not fn.get("is_entrypoint"):
            continue
        qualified = fn.get("qualified_name") or fn.get("name") or "unknown"
        signals = set(fn.get("modifier_guard_signals") or [])
        sources = fn.get("modifier_guard_sources") or []
        if signals.intersection({"tx_origin_eoa", "eoa_named_modifier"}):
            key = ("AA7702-001", qualified)
            if key not in seen:
                findings.append(EIP7702Finding(
                    check_id="AA7702-001",
                    title=(
                        "EIP-7702 reaches tx.origin/EOA modifier gate through "
                        f"{qualified}()"
                    ),
                    severity="CRITICAL",
                    description=(
                        f"`{qualified}()` is externally reachable and uses modifier(s) "
                        f"{', '.join(sources) or 'unknown'} that enforce an EOA-only "
                        "assumption. After EIP-7702, a delegated EOA can pass this "
                        "gate while executing arbitrary delegated code."
                    ),
                    location=f"{qualified}:semantic",
                    cwe="CWE-284",
                    recommendation=(
                        "Remove the EOA-only modifier from externally reachable paths. "
                        "Use explicit authorization, EIP-712 approvals, or protocol "
                        "logic that does not depend on the EOA/contract distinction."
                    ),
                    confidence=0.93,
                ))
                seen.add(key)
        if "code_length_eoa_gate" in signals:
            key = ("AA7702-002", qualified)
            if key not in seen:
                findings.append(EIP7702Finding(
                    check_id="AA7702-002",
                    title=(
                        "EIP-7702 reaches code.length/isContract EOA gate through "
                        f"{qualified}()"
                    ),
                    severity="HIGH",
                    description=(
                        f"`{qualified}()` is externally reachable and uses modifier(s) "
                        f"{', '.join(sources) or 'unknown'} that classify EOAs by "
                        "code length or extcodesize. EIP-7702 makes that boundary "
                        "unsafe because delegated EOAs can carry executable code."
                    ),
                    location=f"{qualified}:semantic",
                    cwe="CWE-697",
                    recommendation=(
                        "Do not use code.length, extcodesize, or isContract() as a "
                        "security boundary. Replace with explicit access control or "
                        "signature-domain checks."
                    ),
                    confidence=0.88,
                ))
                seen.add(key)
    for path in _semantic_ir_reachable_fact_paths(sem, "tx_origin_checks"):
        qualified = path["entrypoint"]
        target = path["target"]
        if qualified == target:
            continue
        key = ("AA7702-001", qualified)
        if key in seen:
            continue
        path_label = " -> ".join(path.get("path") or [qualified, target])
        findings.append(EIP7702Finding(
            check_id="AA7702-001",
            title=(
                "EIP-7702 reaches tx.origin EOA gate through "
                f"{qualified}()"
            ),
            severity="CRITICAL",
            description=(
                f"`{qualified}()` is externally reachable and reaches "
                f"`tx.origin == msg.sender` in `{target}` via `{path_label}`. "
                "After EIP-7702, a delegated EOA can pass this gate while "
                "executing arbitrary delegated code."
            ),
            location=f"{qualified}:semantic",
            cwe="CWE-284",
            recommendation=(
                "Remove the tx.origin EOA gate from externally reachable paths. "
                "Use explicit authorization, EIP-712 approvals, or protocol "
                "logic that does not depend on the EOA/contract distinction."
            ),
            confidence=0.91,
        ))
        seen.add(key)
    # Build a quick lookup of access-controlled qualified names. The deep
    # semantic-path emissions below are advisories about externally
    # reachable delegated-account paths; if the function carries a real
    # access gate (modifier or inline check resolved by the index), the
    # advisory becomes self-harm-shaped and we drop it.
    access_controlled_qnames = {
        fn.get("qualified_name") for fn in index.get("functions") or []
        if fn.get("is_access_controlled")
    }
    eoa_signal_qnames = {
        fn.get("qualified_name") for fn in index.get("functions") or []
        if set(fn.get("modifier_guard_signals") or []).intersection(
            {"tx_origin_eoa", "eoa_named_modifier", "code_length_eoa_gate"}
        )
    }

    for contract_name, model in sorted((index.get("delegation_models") or {}).items()):
        if not model.get("is_delegation_like"):
            continue
        for qualified in model.get("external_delegatecall_functions") or []:
            key = ("AA7702-006", qualified)
            if key in seen:
                continue
            # Suppress when the path is access-controlled AND the
            # modifier(s) on it do not themselves carry an EOA-gate
            # signal. AA7702-001 picks up the EOA-modifier case
            # separately above.
            if (
                qualified in access_controlled_qnames
                and qualified not in eoa_signal_qnames
            ):
                seen.add(key)
                continue
            findings.append(EIP7702Finding(
                check_id="AA7702-006",
                title=(
                    "EIP-7702 delegation target reaches nested delegatecall through "
                    f"{qualified}()"
                ),
                severity="HIGH",
                description=(
                    f"`{qualified}()` is an externally reachable delegated-account path "
                    "that performs delegatecall. Under EIP-7702, this creates a second "
                    "execution-context switch against the EOA's storage and should be "
                    "proved with a fork trace before claiming impact."
                ),
                location=f"{qualified}:semantic",
                cwe="CWE-693",
                recommendation=(
                    "Avoid delegatecall inside delegated-account implementations. If it "
                    "is unavoidable, bind authorization and storage assumptions to the "
                    "delegated account model and confirm the exact storage diff."
                ),
                confidence=0.86,
            ))
            seen.add(key)
        if not model.get("uses_erc7201"):
            owner_like = model.get("owner_like_state_variables") or []
            raw_count = int(model.get("raw_storage_variable_count") or 0)
            initializers = model.get("initializer_functions") or []
            if owner_like and not initializers:
                key = ("AA7702-007", contract_name)
                if key not in seen:
                    findings.append(EIP7702Finding(
                        check_id="AA7702-007",
                        title=(
                            "EIP-7702 delegation target has owner/admin storage with "
                            "no initializer path"
                        ),
                        severity="CRITICAL",
                        description=(
                            f"`{contract_name}` has owner-like storage "
                            f"{', '.join(owner_like[:4])} but no initializer function in "
                            "the semantic model. A delegated EOA starts with zeroed "
                            "storage, so this needs a storage-diff proof or refutation."
                        ),
                        location=f"{contract_name}:semantic-storage",
                        cwe="CWE-665",
                        recommendation=(
                            "Use an atomic initializer with a permanent guard and ERC-7201 "
                            "namespaced storage for delegated-account state."
                        ),
                        confidence=0.90,
                    ))
                    seen.add(key)
            elif raw_count >= 3:
                key = ("AA7702-007", contract_name)
                if key not in seen:
                    findings.append(EIP7702Finding(
                        check_id="AA7702-007",
                        title=(
                            "EIP-7702 delegation target has raw storage layout without "
                            "ERC-7201 namespace"
                        ),
                        severity="HIGH",
                        description=(
                            f"`{contract_name}` has {raw_count} storage-backed state "
                            "variables in a delegated-account surface. Switching "
                            "delegation targets can collide with these slots unless "
                            "storage is namespaced."
                        ),
                        location=f"{contract_name}:semantic-storage",
                        cwe="CWE-665",
                        recommendation=(
                            "Use ERC-7201 namespaced storage and prove slot isolation "
                            "with a fork/local storage diff."
                        ),
                        confidence=0.80,
                    ))
                    seen.add(key)
        # Index functions by qualified name once for the AA7702-008
        # call-graph lookups below.
        functions_by_qname = {
            fn.get("qualified_name"): fn
            for fn in index.get("functions") or []
        }

        for qualified in model.get("unguarded_initializer_functions") or []:
            key = ("AA7702-008", qualified)
            if key in seen:
                continue
            # When the unguarded initializer body delegates to an
            # `_initialize*` / `_init_*` helper (Solady's
            # `_initializeOwner`, OZ's `__Foo_init`, etc.), the
            # one-time guard lives in the called helper. The semantic
            # index records the direct call but does not follow it; we
            # treat the call as evidence the guard exists and surface
            # AA7702-008 only when the body itself is empty of
            # initializer helpers. Falls back to a direct text search
            # on the surrounding source so cross-file inheritance
            # (Solady's Ownable._initializeOwner) is covered without
            # requiring the base contract to be in the same scan input.
            fn_info = functions_by_qname.get(qualified) or {}
            direct_calls = [
                str(c) for c in (fn_info.get("direct_calls") or [])
            ]
            if any(
                c.startswith("_init") or c.startswith("__init")
                or c.startswith("_initialize") or c.startswith("__initialize")
                for c in direct_calls
            ):
                seen.add(key)
                continue
            fn_name = (
                qualified.split(".", 1)[1]
                if "." in qualified else qualified
            )
            if source and fn_name:
                fn_open_re = re.compile(
                    r"function\s+" + re.escape(fn_name) + r"\s*\("
                )
                m = fn_open_re.search(source)
                if m:
                    body_start = source.find("{", m.end())
                    if body_start >= 0:
                        depth = 0
                        for j in range(body_start, len(source)):
                            ch = source[j]
                            if ch == "{":
                                depth += 1
                            elif ch == "}":
                                depth -= 1
                                if depth == 0:
                                    body = source[body_start:j]
                                    if re.search(
                                        r"\b_+initialize\w*\s*\(|"
                                        r"\b_+init\w*\s*\(|"
                                        r"\binitializer\b|"
                                        r"\breinitializer\s*\(",
                                        body,
                                    ):
                                        seen.add(key)
                                        body = None
                                    break
                        if body is None:
                            continue
            findings.append(EIP7702Finding(
                check_id="AA7702-008",
                title=f"EIP-7702 initializer path `{qualified}()` lacks a one-time guard",
                severity="CRITICAL",
                description=(
                    f"`{qualified}()` is externally reachable on a delegation-like "
                    "contract and the semantic model found no initializer modifier, "
                    "`_initialized` check, or one-time guard. This should be confirmed "
                    "by proving whether a third party can initialize delegated EOA state."
                ),
                location=f"{qualified}:semantic",
                cwe="CWE-362",
                recommendation=(
                    "Guard initializer/reinitializer paths and execute initialization "
                    "atomically with delegation setup."
                ),
                confidence=0.88,
            ))
            seen.add(key)
        proxy_flags = model.get("proxy_risk_flags") or []
        if proxy_flags:
            key = ("AA7702-009", contract_name)
            if key not in seen:
                findings.append(EIP7702Finding(
                    check_id="AA7702-009",
                    title=f"Proxy-like upgrade surface inside EIP-7702 target `{contract_name}`",
                    severity="CRITICAL",
                    description=(
                        f"`{contract_name}` is delegation-like and has proxy risk flags "
                        f"{', '.join(proxy_flags)}. Proxy implementation/admin slots live "
                        "in the delegated EOA storage context and require proof or "
                        "explicit refutation."
                    ),
                    location=f"{contract_name}:semantic-proxy",
                    cwe="CWE-669",
                    recommendation=(
                        "Do not combine upgradeable proxy patterns with delegated-account "
                        "implementations unless storage/admin behavior is explicitly "
                        "modeled and proven safe."
                    ),
                    confidence=0.89,
                ))
                seen.add(key)
    return findings


def _finding_function_name(finding: "EIP7702Finding") -> Optional[str]:
    """Extract the function name from ``finding.location`` if it carries one.

    Locations are emitted by the detectors in one of three shapes:
    ``"<fname>():L<line>"``, ``"modifier <name>:L<line>"``, or contract-level
    strings like ``"contract-level"`` / ``"L<line>"``. Only the first form
    yields a usable function name.
    """
    loc = getattr(finding, "location", "") or ""
    match = re.match(r"([A-Za-z_]\w*)\s*\(\s*\)", loc)
    if match:
        return match.group(1)
    return None


def _function_is_access_controlled_by_index(
    finding: "EIP7702Finding", sem: dict
) -> bool:
    """AST-backed access-control check.

    Uses the project semantic index when deep mode is on. The index's
    ``is_access_controlled`` flag already accounts for inherited modifiers
    via linearised bases — i.e. cross-file inheritance is handled by
    construction, which the regex pass cannot do.
    """
    if not sem:
        return False
    index = sem.get("semantic_index") or {}
    functions = index.get("functions") or []
    if not functions:
        return False
    fname = _finding_function_name(finding)
    if not fname:
        return False
    # Multiple contracts can define a function with the same name. The
    # location string already carries the function name; we treat any
    # matching ``is_access_controlled=True`` entry as evidence the call
    # site is gated. If ANY entry says False and NONE say True, suppression
    # does not apply.
    matched = [
        fn for fn in functions
        if (fn.get("name") == fname)
        or (fn.get("qualified_name", "").endswith(f".{fname}"))
    ]
    if not matched:
        return False
    return any(fn.get("is_access_controlled") for fn in matched)


def _suppress_finding(
    content: str,
    finding: "EIP7702Finding",
    ctx: dict,
    fname: str | None = None,
) -> bool:
    """Universal, context-aware suppression. Returns True to drop the finding.
    Encodes 'flag only if pattern present AND no protection' per check."""
    cid = finding.check_id
    clean = _strip_comments(content)
    semantic_files = ctx.get("semantic_files") or {}
    sem = semantic_files.get(fname) if fname else None
    if sem is None:
        sem = _semantic_context_for_source(content)

    # AST / semantic-index-backed access-control suppression. Runs only
    # when ``chainedr scan --deep`` has populated ``sem["semantic_index"]``;
    # silently no-ops in regex-only mode. Covers AA7702-001 / 002 / 006 —
    # the three rules where access control is the primary suppression
    # signal and cross-file inheritance is the regex layer's blind spot.
    if cid in ("AA7702-001", "AA7702-002", "AA7702-006"):
        if _function_is_access_controlled_by_index(finding, sem):
            sem_analysis = str(
                (finding.semantic_context or {}).get("analysis") or ""
            )
            # Keep the alias-flow / state-flow proofs visible — they
            # explicitly cite the un-guarded aliasing path.
            if sem_analysis not in (
                "intra_function_alias_flow",
                "cross_function_state_alias_flow",
            ):
                return True
    if cid == "AA7702-001":
        # Alias-flow and cross-function state-flow proofs trump the IR's
        # literal `tx.origin` token search — the IR can't see that
        # `initiator` aliases `tx.origin` through a local or state
        # assignment, so a "no tx_origin_checks fact reachable" verdict
        # is wrong by construction for those analysis modes.
        sem_analysis = str(
            (finding.semantic_context or {}).get("analysis") or ""
        )
        if sem_analysis not in (
            "intra_function_alias_flow",
            "cross_function_state_alias_flow",
        ):
            if _ir_proves_unreachable_fact(sem, "tx_origin_checks"):
                return True
    # AA7702-005 (missing revocation): only actionable when the contract keeps
    # delegation-dependent state or reaches storage writes through an entrypoint.
    if cid == "AA7702-005":
        if (
            _semantic_ir_lacks_fact(sem, "storage_writes")
            and not _source_has_storage_layout_hint(clean)
        ):
            return True
        if _ir_proves_unreachable_fact(sem, "storage_writes"):
            return True
    # AA7702-004 (cross-chain replay): only real when the contract actually
    # verifies signatures AND no chain_id is bound anywhere (file or project).
    if cid == "AA7702-004":
        has_auth_context = bool(re.search(
            r"(authorization|ecrecover|ECDSA|isValidSignature|chainId|chain_id|7702|setCode)",
            clean,
            re.I,
        ))
        if not has_auth_context:
            return True
        verifies_sig = bool(re.search(
            r"(ecrecover\s*\(|ECDSA\.recover\s*\(|isValidSignature\s*\(|"
            r"SignatureChecker|authorization|chainId|chain_id)",
            clean,
            re.I,
        ))
        binds_chain = ctx.get("binds_chain_id") or bool(_CHAIN_BIND_RE.search(clean))
        if (not verifies_sig) or binds_chain:
            return True
    # AA7702-007 (storage collision): not a risk when the project uses ERC-7201
    # namespaced storage — collisions are structurally prevented.
    if cid == "AA7702-007":
        if ctx.get("uses_erc7201") or bool(_ERC7201_RE.search(clean)):
            return True
    # AA7702-013 (gas griefing) / AA7702-011 (batch replay): in an ERC-4337
    # system gas limits and nonces are enforced by the EntryPoint, not per
    # contract. Suppress only when the project actually wires an EntryPoint.
    # AA7702-012 (meta-tx / permit nonce): same rationale — in ERC-4337 the
    # UserOperation nonce is enforced by the EntryPoint, so a per-contract nonce
    # gap is not exploitable (verified FP on Safe7579 / Ambire).
    if cid in ("AA7702-013", "AA7702-011", "AA7702-012"):
        if ctx.get("uses_entrypoint") or sem.get("uses_entrypoint"):
            return True
    # Complete EIP-712 + nonce + verifying-contract + ERC-1271 style signature
    # models are already bound to the account context; keep raw signature smell
    # findings out of the default path when that full structure is present.
    if cid in ("AA7702-010", "AA7702-016"):
        if sem.get("complete_signature_model"):
            return True
        if cid == "AA7702-016" and (
            sem.get("uses_erc1271") or re.search(r"\b(IERC1271|EIP1271|isValidSignature)\b", clean)
        ):
            return True
    # A callback surface with an explicit reentrancy guard is not the delegated
    # EOA callback bug class ChainEDR is trying to prove.
    if cid == "AA7702-003":
        if sem.get("has_reentrancy_guard"):
            return True
        if (
            "function sendValue(address payable recipient, uint256 amount)" in clean
            and "Address: unable to send value" in clean
            and "sendValue()" in (getattr(finding, "location", "") or "")
        ):
            return True
        is_standalone_library = (
            bool(re.search(r"^\s*library\s+\w+", clean, re.M))
            and not bool(re.search(r"^\s*contract\s+\w+", clean, re.M))
        )
        if is_standalone_library:
            return True
    # OZ-style Initializable construction checks use address(this).code.length
    # only to distinguish constructor execution, not EOAs from contracts.
    if cid == "AA7702-002":
        if _ir_proves_unreachable_fact(sem, "code_size_checks"):
            return True
        if (
            re.search(r"\bmodifier\s+initializer\s*\(", clean)
            and re.search(r"!\s*Address\.isContract\s*\(\s*address\s*\(\s*this\s*\)\s*\)", clean)
            and re.search(r"\b_initialized\b", clean)
        ):
            return True
        if (
            re.search(r"\bmodifier\s+initializer\s*\(", clean)
            and (
                "address(this).code.length == 0" in clean
                or re.search(r"!\s*Address\.isContract\s*\(\s*address\s*\(\s*this\s*\)\s*\)", clean)
            )
            and re.search(r"\binitialized\s*==\s*1\b", clean)
            and re.search(r"\bconstruction\b", clean)
        ):
            return True
        # CREATE2 clone deployment checks use code.length to ask "has this
        # deterministic receiver already been deployed?", not "is this user an
        # EOA?". EIP-7702 does not let an attacker sign for a random CREATE2
        # address, so this is not the delegated-EOA boundary.
        line_no = getattr(finding, "line", None)
        if line_no is None:
            loc_match = re.search(r":L(\d+)\b", getattr(finding, "location", "") or "")
            line_no = int(loc_match.group(1)) if loc_match else None
        if line_no is not None:
            lines = clean.splitlines()
            idx = max(0, int(line_no) - 1)
            window = "\n".join(lines[max(0, idx - 20): min(len(lines), idx + 20)])
            # `AddressNotContract` checks are contract-address configuration
            # guards (implementation/registry/connector/beacon/etc.), not
            # "EOA only" gates. A delegated EOA having code is not a bypass of
            # this invariant.
            if ".code.length == 0" in window and "AddressNotContract" in window:
                return True
            if ".code.length == 0" in window and re.search(
                r"(InvalidImplementation|newImplementation|implementation_|\b_setImplementation\b)",
                window,
            ):
                return True
            # ERC-1271 signature routing via `signer.code.length > 0` —
            # the branch picks 1271 for smart-contract signers and
            # ecrecover for plain EOAs. That is exactly what 7702-aware
            # validators should do; AA7702-002 should NOT fire.
            if re.search(r"\.code\.length\s*[><]\s*0", window) and re.search(
                r"(isValidSignature|IERC1271|EIP1271|0x1626ba7e|_1271_MAGIC|SignatureChecker)",
                window,
            ):
                return True
            if ".isContract(" in window or "isContract(" in window:
                # ERC-1271 signature routing uses isContract(signer) to choose
                # between ECDSA and isValidSignature(), not to reject delegated EOAs.
                if re.search(r"(signer|signature)", window, re.I) and re.search(
                    r"(IERC1271|EIP1271|isValidSignature)", clean,
                ):
                    return True
                # Deploy/status checks ask whether a deterministic wallet/proxy
                # already exists. They are not EOA-only security boundaries.
                if re.search(
                    r"(_getDeployed|isDeployed|computed\w*Address|compute\w*|"
                    r"predictDeterministicAddress|cloneDeterministic|deployment)",
                    window,
                    re.I,
                ):
                    return True
                # Admin config guards require implementation/module/beacon/etc.
                # addresses to be contracts. A delegated EOA cannot exploit this
                # as an EOA/contract privilege boundary.
                if re.search(
                    r"(newImplementation|implementation|newBeacon|beacon|version|"
                    r"forwarder|module|connector|registry|target|_address)",
                    window,
                    re.I,
                ) and re.search(r"(onlyOwner|onlyAdmin|upgrade|set|register|ERC1967)", clean, re.I):
                    return True
            if (
                ".code.length == 0" in window
                and "predictDeterministicAddress" in window
                and "cloneDeterministic" in window
            ):
                return True
    # Factory context: a *Factory's `code.length` check is a deploy-status /
    # constructor guard (is the implementation deployed?), not a runtime EOA gate,
    # and its callbacks run at deploy time — neither is the 7702 risk these flag.
    is_factory = bool(re.search(r"\b(contract|library)\s+\w*Factory\b", clean))
    if cid in ("AA7702-002", "AA7702-003") and is_factory:
        return True
    # AA7702-009 (ERC-1967 proxy): only a real proxy if it actually delegates
    # (delegatecall + fallback). A file that merely *defines/references* the
    # ERC-1967 slot constant (constants/lib) is not an upgradeable proxy.
    if cid == "AA7702-009":
        has_fallback_entrypoint = bool(re.search(r"\bfallback\s*\(", clean))
        if "delegatecall" not in clean and not has_fallback_entrypoint:
            return True
    return False


def _ir_proves_unreachable_fact(sem: dict, fact_key: str) -> bool:
    reachability = _ir_fact_reachability(sem, fact_key)
    if not reachability or reachability["uncertain"]:
        return False
    if not reachability["entrypoints"]:
        return True
    return not reachability["paths"]


def _semantic_ir_lacks_fact(sem: dict, fact_key: str) -> bool:
    functions = (sem.get("semantic_ir") or {}).get("functions") or []
    if not functions:
        return False
    return not any(function.get(fact_key) for function in functions)


def _source_has_storage_layout_hint(clean: str) -> bool:
    if re.search(r"\b(sstore|assembly)\b", clean, re.I):
        return True
    return any(_STORAGE_VAR_RE.match(line) for line in clean.splitlines())


def _semantic_ir_reachable_fact_paths(sem: dict, fact_key: str) -> list[dict]:
    reachability = _ir_fact_reachability(sem, fact_key)
    if not reachability or reachability["uncertain"]:
        return []
    return reachability["paths"]


def _ir_fact_reachability(sem: dict, fact_key: str) -> dict | None:
    semantic_ir = sem.get("semantic_ir") or {}
    call_graph = sem.get("call_graph") or {}
    functions = semantic_ir.get("functions") or []
    if not functions or not call_graph:
        return None
    fact_nodes = {
        function.get("qualified_name")
        for function in functions
        if function.get("qualified_name") and function.get(fact_key)
    }
    if not fact_nodes:
        return None
    uncertain = bool(call_graph.get("unresolved_edges"))

    nodes = {
        node.get("qualified_name"): node
        for node in call_graph.get("nodes") or []
        if node.get("qualified_name")
    }
    entrypoints = {
        name for name, node in nodes.items()
        if node.get("kind") != "modifier"
        and node.get("visibility") in {"public", "external"}
    }

    graph_edges: dict[str, set[str]] = {}
    for edge in call_graph.get("edges") or []:
        if edge.get("uncertainty"):
            uncertain = True
            continue
        if edge.get("kind") not in {"modifier", "internal_call"}:
            continue
        source = edge.get("source")
        target = edge.get("target")
        if source and target:
            graph_edges.setdefault(source, set()).add(target)

    paths: list[dict] = []
    for entrypoint in sorted(entrypoints):
        reachable = {entrypoint}
        stack = [(entrypoint, [entrypoint])]
        while stack:
            source, path = stack.pop()
            if source in fact_nodes:
                paths.append({
                    "entrypoint": entrypoint,
                    "target": source,
                    "path": path,
                })
            for target in sorted(graph_edges.get(source, set())):
                if target in reachable:
                    continue
                reachable.add(target)
                stack.append((target, [*path, target]))

    return {
        "fact_nodes": fact_nodes,
        "entrypoints": entrypoints,
        "paths": paths,
        "uncertain": uncertain,
    }


def _semantic_ir_fact_reachability_summary(sem: dict, fact_key: str) -> dict:
    reachability = _ir_fact_reachability(sem, fact_key)
    if not reachability:
        return {}
    paths = [
        {
            "entrypoint": str(path.get("entrypoint") or ""),
            "target": str(path.get("target") or ""),
            "path": [str(node) for node in path.get("path") or []],
        }
        for path in reachability.get("paths") or []
    ]
    return {
        "entrypoints": sorted(str(name) for name in reachability["entrypoints"] if name),
        "fact_nodes": sorted(str(name) for name in reachability["fact_nodes"] if name),
        "path_count": len(paths),
        "paths": paths[:12],
        "truncated": len(paths) > 12,
        "uncertain": bool(reachability.get("uncertain")),
    }


def _semantic_ir_fact_sample(facts: list[dict], limit: int = 6) -> list[dict]:
    sample: list[dict] = []
    for fact in facts[:limit]:
        if not isinstance(fact, dict):
            continue
        item = {
            "kind": str(fact.get("kind") or ""),
            "name": str(fact.get("name") or ""),
        }
        source = fact.get("source") or {}
        if isinstance(source, dict):
            item["source"] = {
                key: source[key]
                for key in ("file", "start", "length", "line", "column")
                if key in source
            }
        detail = fact.get("detail") or {}
        if isinstance(detail, dict) and detail:
            item["detail"] = {
                key: detail[key]
                for key in sorted(detail)[:4]
            }
        sample.append(item)
    return sample


def _semantic_ir_storage_model(sem: dict) -> dict:
    semantic_ir = sem.get("semantic_ir") or {}
    functions = semantic_ir.get("functions") or []
    if not functions:
        return {}

    storage_functions: list[dict] = []
    read_symbols: set[str] = set()
    write_symbols: set[str] = set()
    read_count = 0
    write_count = 0

    for function in functions:
        reads = [
            fact for fact in (function.get("storage_reads") or [])
            if isinstance(fact, dict)
        ]
        writes = [
            fact for fact in (function.get("storage_writes") or [])
            if isinstance(fact, dict)
        ]
        if not reads and not writes:
            continue
        read_count += len(reads)
        write_count += len(writes)
        read_symbols.update(str(fact.get("name") or "") for fact in reads if fact.get("name"))
        write_symbols.update(str(fact.get("name") or "") for fact in writes if fact.get("name"))
        entry = {
            "function": function.get("qualified_name") or function.get("name") or "unknown",
            "visibility": function.get("visibility") or "",
            "kind": function.get("kind") or "function",
            "read_count": len(reads),
            "write_count": len(writes),
        }
        if reads:
            entry["reads"] = _semantic_ir_fact_sample(reads)
        if writes:
            entry["writes"] = _semantic_ir_fact_sample(writes)
        storage_functions.append(entry)

    if not storage_functions:
        return {}

    model = {
        "analysis_depth": semantic_ir.get("analysis_depth"),
        "compiler_status": semantic_ir.get("compiler_status"),
        "storage_read_count": read_count,
        "storage_write_count": write_count,
        "storage_symbols": {
            "reads": sorted(read_symbols),
            "writes": sorted(write_symbols),
        },
        "functions": storage_functions[:12],
        "functions_truncated": len(storage_functions) > 12,
    }

    read_reachability = _semantic_ir_fact_reachability_summary(sem, "storage_reads")
    if read_reachability:
        model["reachable_storage_reads"] = read_reachability
    write_reachability = _semantic_ir_fact_reachability_summary(sem, "storage_writes")
    if write_reachability:
        model["reachable_storage_writes"] = write_reachability
        if write_reachability.get("path_count"):
            model["review_signal"] = "reachable_storage_write"
    if not model.get("review_signal"):
        model["review_signal"] = "storage_layout_signal"
    return model


def _attach_storage_ir_evidence(finding: "EIP7702Finding", sem: dict) -> None:
    if finding.check_id not in {"AA7702-005", "AA7702-007", "AA7702-020"}:
        return
    storage_model = _semantic_ir_storage_model(sem)
    if not storage_model:
        return
    finding.semantic_context = dict(finding.semantic_context or sem)
    finding.semantic_context["storage_model"] = storage_model


def detect_delegatecall_from_delegation(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    if not _is_delegation_target(source):
        return findings

    lines = source.splitlines()
    seen_fns: set[str] = set()

    # If storage layout is NOT pinned (raw state variables, no slot
    # constants, no namespaced struct accessor), then `msg.sender == owner`
    # inside the delegation target reads from the EOA's zero storage and
    # the access gate provides no protection. In that regime AA7702-006
    # should still fire even on access-controlled functions. When storage
    # IS pinned (Kernel / Nexus / Solady / Ithaca), the owner slot is at a
    # collision-free location and the access gate works as intended.
    pinned = _has_pinned_storage_layout(source)

    for i, line in enumerate(lines):
        m = _DELEGATECALL_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue
        # Access-control gating only suppresses when the storage layout
        # itself is collision-safe. Otherwise the gate runs against a
        # zeroed EOA slot and is bypassable.
        if pinned and _function_is_access_gated(lines, i):
            continue
        fn_name = _enclosing_function(lines, i)
        # Internal-only / private functions are not directly attacker-
        # reachable. Bootstrap delegatecall patterns (Nexus
        # `_initializeAccount`, Solady `_install` helpers, etc.) sit in
        # internal helpers whose external callers are themselves
        # signature-gated. The detector cannot follow the call graph
        # back from regex; drop the alert for internal helpers and
        # rely on the external caller's own gating to surface the real
        # issue, if any.
        fn_header_idx = i
        for j in range(i, max(i - 20, -1), -1):
            if re.match(r"^\s*function\s+", lines[j]):
                fn_header_idx = j
                break
        fn_header = " ".join(lines[fn_header_idx:fn_header_idx + 3])
        if not re.search(r"\b(public|external)\b", fn_header):
            continue
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)

        findings.append(EIP7702Finding(
            check_id="AA7702-006",
            title=f"delegatecall in EIP-7702 delegation target {fn_name}()",
            severity="HIGH",
            description=(
                f"`{fn_name}()` uses delegatecall inside what appears to be an "
                f"EIP-7702 delegation target contract. When an EOA delegates to "
                f"this contract, the code runs in the EOA's context. A nested "
                f"delegatecall creates double context confusion: the inner call's "
                f"code accesses the EOA's storage and balance, but msg.sender "
                f"changes to the delegation target. This can break authorization "
                f"checks that rely on msg.sender == owner."
            ),
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-693",
            recommendation=(
                "Avoid delegatecall in EIP-7702 delegation target contracts. "
                "Use regular call() instead, or if delegatecall is required, "
                "ensure all authorization checks use tx.origin or a stored "
                "owner address rather than msg.sender."
            ),
            confidence=0.78,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-007: Storage collision between EOA and delegation target
# ─────────────────────────────────────────────────────────────────────────────
# When an EOA delegates to a contract, the contract's code executes against
# the EOA's (initially empty) storage. If the delegation target was designed
# as a standalone contract with its own storage layout (state variables,
# mappings), it reads zeros for all slots — potentially bypassing
# authorization checks, initial balances, or config. Worse: if the EOA
# switches delegation targets, the second target's storage layout collides
# with whatever the first target wrote.
#
# This is analogous to the proxy storage collision vulnerability
# (ERC-1967 solved for proxies), but nobody detects it for 7702 delegation.

_STORAGE_VAR_RE = re.compile(
    r"^\s*(address|uint\d*|int\d*|bool|bytes\d*|string|mapping)\s+"
    r"(public\s+|private\s+|internal\s+)?"
    r"(\w+)\s*[;=]",
)
_INITIALIZER_RE = re.compile(
    r"(initialize|init|setup|constructor)\s*\(",
    re.IGNORECASE,
)
_OWNER_SLOT_RE = re.compile(
    r"(owner|admin|manager|controller)\s*[=;]|_owner\b",
    re.IGNORECASE,
)

# A pinned storage layout protects a delegation target from the redelegation
# storage-collision class regardless of the number of state variables. Three
# concrete shapes are recognised:
#   - ERC-7201 macro / comment (``@custom:storage-location erc7201:<id>``);
#   - manual slot constants (``bytes32 ... constant _X_SLOT = keccak256(...)``
#     / ``constant X_LOCATION = 0x...``) — the convention used by Kernel,
#     Solady, OZ TransparentUpgradeableProxy, and many bespoke kernels;
#   - a namespaced-struct accessor — ``function _getXStorage() ... pure ...
#     returns (X storage $...)`` — the convention used by Nexus and Solady
#     ERC4337 to expose a single storage struct rooted at a fixed slot.
_ERC7201_LOC_RE = re.compile(
    r"(@custom:storage-location\s+erc7201:|erc7201:)",
    re.I,
)
_MANUAL_SLOT_CONSTANT_RE = re.compile(
    r"bytes32\s+(?:public\s+|private\s+|internal\s+)?"
    r"constant\s+\w*(SLOT|LOCATION|POSITION|STORAGE)\b",
    re.I,
)
# Use-site: imported slot constants written via sstore/sload, e.g.
# `sstore(ERC1967_IMPLEMENTATION_SLOT, x)`. The definition lives in
# another file but the use is unambiguous.
_SLOT_CONSTANT_USE_RE = re.compile(
    r"(?:sstore|sload)\s*\(\s*\w*(SLOT|LOCATION|POSITION|STORAGE)\b",
    re.I,
)
# Definition: `function _getXStorage() internal ... returns (X storage $)`.
_NAMESPACED_STORAGE_GETTER_DEF_RE = re.compile(
    r"function\s+_?get\w*Storage\s*\([^)]*\)\s+"
    r"internal\s+(?:pure\s+|view\s+)?returns\s*\(\s*\w+\s+storage\s+",
)
# Use-site: `Whatever storage X = _getAccountStorage()` /
# `_getFooStorage().bar` — Nexus, Solady ERC4337, and any account that
# inherits the storage helper from a sibling file uses this shape.
_NAMESPACED_STORAGE_GETTER_USE_RE = re.compile(
    r"_get\w*Storage\s*\(\s*\)",
)


def _has_pinned_storage_layout(source: str) -> bool:
    clean = _strip_comments(source)
    return bool(
        _ERC7201_LOC_RE.search(source)        # ERC-7201 lives in the comment
        or _MANUAL_SLOT_CONSTANT_RE.search(clean)
        or _SLOT_CONSTANT_USE_RE.search(clean)
        or _NAMESPACED_STORAGE_GETTER_DEF_RE.search(clean)
        or _NAMESPACED_STORAGE_GETTER_USE_RE.search(clean)
    )


def detect_storage_collision(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    if not _is_delegation_target(source):
        return findings

    # If the contract pins its storage explicitly — either via the
    # ERC-7201 macro/comment, a manual slot constant
    # (`bytes32 constant _X_SLOT = keccak256(...)` or
    # `bytes32 private constant X_LOCATION = 0x...`), or a namespaced-
    # struct accessor (`function _getAccountStorage() internal pure
    # returns (AccountStorage storage $s)` style used by Nexus / Kernel
    # / Solady ERC4337) — the storage layout is collision-safe across
    # delegation target switches by construction. AA7702-007 should
    # NOT fire here.
    if _has_pinned_storage_layout(source):
        return findings

    lines = source.splitlines()
    state_vars: list[tuple[str, int]] = []

    for i, line in enumerate(lines):
        m = _STORAGE_VAR_RE.match(line)
        if m:
            state_vars.append((m.group(3), i + 1))

    if not state_vars:
        return findings

    has_owner = any(_OWNER_SLOT_RE.search(line) for line in lines)
    has_init = _INITIALIZER_RE.search(source)

    if has_owner and not has_init:
        findings.append(EIP7702Finding(
            check_id="AA7702-007",
            title="Storage collision risk: delegation target has owner without initializer",
            severity="CRITICAL",
            description=(
                f"This EIP-7702 delegation target has {len(state_vars)} state variables "
                f"including an owner/admin field, but no initializer function. When an EOA "
                f"delegates to this contract, all storage slots are zero — including the "
                f"owner. An attacker can call any onlyOwner function immediately after "
                f"delegation because owner == address(0) or owner == msg.sender checks "
                f"against zeroed storage. State vars: "
                + ", ".join(f"`{n}` (slot ~{i})" for n, i in state_vars[:5])
            ),
            location=f"L{state_vars[0][1]}",
            cwe="CWE-665",
            recommendation=(
                "Use an initializer pattern (OpenZeppelin Initializable) and call it "
                "atomically with the 7702 delegation setup. Mark the initializer with "
                "a storage flag to prevent re-initialization. Consider using "
                "ERC-7201 namespaced storage to avoid slot collisions."
            ),
            confidence=0.85,
        ))
    elif len(state_vars) >= 3:
        findings.append(EIP7702Finding(
            check_id="AA7702-007",
            title=f"Storage collision risk: delegation target has {len(state_vars)} state variables",
            severity="HIGH",
            description=(
                f"This delegation target defines {len(state_vars)} state variables. "
                f"When an EOA delegates to it, these map to the EOA's storage slots "
                f"(which are initially zero). If the EOA later switches to a different "
                f"delegation target, the new target's storage layout collides with "
                f"whatever was written. This can corrupt balances, authorization state, "
                f"or configuration. Use ERC-7201 namespaced storage."
            ),
            location=f"L{state_vars[0][1]}",
            cwe="CWE-665",
            recommendation=(
                "Use ERC-7201 (namespaced storage layout) with a unique namespace "
                "per delegation target. This prevents storage collisions when an EOA "
                "switches between delegation targets."
            ),
            confidence=0.70,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-008: Initialization race condition
# ─────────────────────────────────────────────────────────────────────────────
# A delegation target may require initialization (like a proxy). If the
# initialization is not atomic with the delegation setup (same tx), an
# attacker can front-run the init call after the delegation is set, taking
# ownership of the EOA's delegated execution context.

_INIT_FN_RE = re.compile(
    r"function\s+(initialize|init|setup)\s*\(",
)
_INIT_GUARD_RE = re.compile(
    r"(initializer|initialized|_initialized|_initializing)",
)


def detect_initialization_race(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    if not _is_delegation_target(source):
        return findings

    init_fns = list(_INIT_FN_RE.finditer(source))
    if not init_fns:
        return findings

    has_guard = _INIT_GUARD_RE.search(source)
    lines = source.splitlines()

    for m in init_fns:
        fn_name = m.group(1)
        line_num = source[:m.start()].count("\n") + 1

        fn_start = line_num - 1
        fn_header = " ".join(lines[fn_start:min(fn_start + 3, len(lines))])

        is_external = "external" in fn_header or "public" in fn_header
        if not is_external:
            continue

        if not has_guard:
            findings.append(EIP7702Finding(
                check_id="AA7702-008",
                title=f"Initialization race: `{fn_name}()` lacks initializer guard",
                severity="CRITICAL",
                description=(
                    f"EIP-7702 delegation target has public `{fn_name}()` without an "
                    f"initialization guard (no `initializer` modifier or `_initialized` "
                    f"check). After an EOA sets delegation via SET_CODE_TX, anyone can "
                    f"front-run the `{fn_name}()` call in a subsequent tx, taking "
                    f"ownership of the delegated context. The attacker then controls "
                    f"the EOA's code execution and can drain its balance."
                ),
                location=f"{fn_name}():L{line_num}",
                cwe="CWE-362",
                recommendation=(
                    "Use OpenZeppelin's Initializable with the `initializer` modifier. "
                    "Better: batch the delegation and init in a single 7702 tx using "
                    "batch authorization, so init executes atomically with delegation."
                ),
                confidence=0.90,
            ))
        else:
            has_onetime = re.search(r"require\s*\(\s*!?\s*_?initialized", source)
            if not has_onetime:
                findings.append(EIP7702Finding(
                    check_id="AA7702-008",
                    title=f"Weak init guard on `{fn_name}()` — may be re-callable",
                    severity="HIGH",
                    description=(
                        f"`{fn_name}()` has an initialization-related identifier but may "
                        f"not properly prevent re-initialization. In delegation context, "
                        f"an attacker could call init again after the EOA revokes and "
                        f"re-delegates."
                    ),
                    location=f"{fn_name}():L{line_num}",
                    cwe="CWE-362",
                    recommendation=(
                        "Ensure initialization sets a permanent flag in storage that "
                        "prevents any future calls. Use OpenZeppelin's `_disableInitializers()` "
                        "in the constructor."
                    ),
                    confidence=0.55,
                ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-009: ERC-1967 proxy pattern + EIP-7702 delegation conflict
# ─────────────────────────────────────────────────────────────────────────────
# If a delegation target is itself an upgradeable proxy (ERC-1967), the
# proxy storage slots (implementation, admin, beacon) exist in the EOA's
# storage. An attacker might upgrade the proxy's implementation via the
# EOA's context, or the proxy pattern itself breaks under delegation.

_ERC1967_RE = re.compile(
    r"(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"  # impl slot
    r"|_IMPLEMENTATION_SLOT|_ADMIN_SLOT|_BEACON_SLOT"
    r"|ERC1967Upgrade|TransparentUpgradeableProxy|UUPSUpgradeable"
    r"|upgradeTo|upgradeToAndCall)",
)
_PROXY_PATTERN_RE = re.compile(
    r"(Proxy|proxy|PROXY)\s*(contract|is|{)",
)


def detect_proxy_delegation_conflict(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    if not _is_delegation_target(source):
        return findings

    has_proxy = _ERC1967_RE.search(source) or _PROXY_PATTERN_RE.search(source)
    if not has_proxy:
        return findings

    # Modular smart accounts (ZeroDev Kernel, Biconomy Nexus, Alchemy
    # LightAccount, Solady ERC4337) intentionally combine an ERC-1967-
    # style implementation slot with EIP-7702 delegation. The CRITICAL
    # framing of AA7702-009 is wrong for that population — the proxy
    # slot is part of the account architecture, gated by an
    # authentication-controlled upgrade path. If the contract carries
    # any of the well-known 7702-aware account markers we still surface
    # the finding, but at HIGH instead of CRITICAL so reviewers can
    # triage it as an architecture-review item rather than a panic.
    # Runtime markers only — naming the contract "EIP7702Whatever" is not
    # evidence of correct architecture, but the presence of an actual
    # validateUserOp / installModule / EntryPoint integration is.
    _looks_like_intentional_7702_account = bool(re.search(
        r"(_amIERC7702|isERC7702|validateUserOp|validatePaymasterUserOp|"
        r"IAccount|IModularAccount|EntryPoint|"
        r"installModule|uninstallModule|isValidatorInstalled)",
        source,
    ))
    proxy_severity = "HIGH" if _looks_like_intentional_7702_account else "CRITICAL"

    lines = source.splitlines()

    upgrade_lines = []
    for i, line in enumerate(lines):
        if re.search(r"upgradeTo|upgradeToAndCall|_setImplementation", line):
            upgrade_lines.append(i + 1)

    findings.append(EIP7702Finding(
        check_id="AA7702-009",
        title="ERC-1967 proxy pattern in EIP-7702 delegation target",
        severity=proxy_severity,
        description=(
            "This delegation target uses an ERC-1967 upgradeable proxy pattern. "
            "When an EOA delegates to this contract, the proxy's storage slots "
            "(implementation address, admin, beacon) live in the EOA's storage. "
            "This creates two attack vectors: (1) The proxy admin slot is "
            "initially zero in the EOA's storage, so anyone can claim admin "
            "and upgrade the implementation. (2) If the EOA revokes delegation, "
            "the proxy state persists in storage and can be exploited by a new "
            "delegation target that reads those slots."
            + (f" Upgrade functions at: L{', L'.join(str(l) for l in upgrade_lines[:3])}" if upgrade_lines else "")
        ),
        location="contract-level",
        cwe="CWE-669",
        recommendation=(
            "Do not use upgradeable proxy patterns as EIP-7702 delegation targets. "
            "Delegation targets should be immutable contracts with ERC-7201 "
            "namespaced storage. If upgradeability is needed, use the 7702 "
            "re-delegation mechanism itself (send a new SET_CODE_TX)."
        ),
        confidence=0.88,
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-010: ERC-20 permit bypass via delegated EOA
# ─────────────────────────────────────────────────────────────────────────────
# ERC-20 permit() uses ecrecover to verify that the EOA signed an approval.
# Pre-7702, signing = dumb cryptographic operation. Post-7702, a delegated
# EOA can execute code that auto-signs permits or manipulates the approval
# flow, enabling batch drain attacks.

_PERMIT_RE = re.compile(
    r"function\s+permit\s*\(|PERMIT_TYPEHASH|_PERMIT_TYPEHASH|EIP712|nonces\[",
)
_ECRECOVER_IN_PERMIT_RE = re.compile(
    r"ecrecover\s*\(",
)
_PERMIT_DEADLINE_RE = re.compile(
    r"deadline|expiry|validUntil",
    re.IGNORECASE,
)


def detect_permit_bypass(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_permit = _PERMIT_RE.search(source)
    if not has_permit:
        return findings

    has_ecrecover = _ECRECOVER_IN_PERMIT_RE.search(source)
    lines = source.splitlines()

    for i, line in enumerate(lines):
        if re.search(r"function\s+permit\s*\(", line):
            fn_start = i
            fn_body_lines = []
            depth = 0
            for j in range(i, min(i + 50, len(lines))):
                if "{" in lines[j]:
                    depth += lines[j].count("{")
                if "}" in lines[j]:
                    depth -= lines[j].count("}")
                fn_body_lines.append(lines[j])
                if depth <= 0 and j > i:
                    break
            fn_body = "\n".join(fn_body_lines)

            has_delegation_check = bool(re.search(
                r"code\.length|codehash|extcodesize|0xef0100|isDelegated|delegationAware|hasDelegation",
                fn_body, re.IGNORECASE,
            ))
            if has_delegation_check:
                break

            has_iscontract = bool(re.search(r"isContract|code\.length|extcodesize", fn_body))

            findings.append(EIP7702Finding(
                check_id="AA7702-010",
                title="ERC-20 permit() vulnerable to EIP-7702 delegated EOA abuse",
                severity="HIGH",
                description=(
                    "permit() uses ecrecover to verify an EOA's signature for token "
                    "approval. Post-EIP-7702, a delegated EOA can programmatically "
                    "generate and submit permit signatures via its delegation code. "
                    "Attack scenario: (1) Attacker gets victim to delegate to malicious "
                    "contract. (2) Malicious delegation code auto-signs permit() for "
                    "max approval to attacker. (3) Attacker drains all tokens via "
                    "transferFrom(). The permit signature is technically valid — the "
                    "EOA's key signed it — but the owner didn't consciously approve."
                    + (" This permit() also checks isContract — see AA7702-002." if has_iscontract else "")
                ),
                location=f"permit():L{i+1}",
                cwe="CWE-345",
                recommendation=(
                    "Add a delegation awareness check: query if the signer address "
                    "has the 0xef0100 delegation designator prefix in its code. If so, "
                    "require additional verification (e.g., a time delay, a separate "
                    "confirmation tx, or a multi-sig approval). Consider implementing "
                    "ERC-7702-aware permit that checks `codehash` of the signer."
                ),
                confidence=0.80,
            ))
            break

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-011: Batch authorization ordering / replay
# ─────────────────────────────────────────────────────────────────────────────
# EIP-7702 supports multiple authorization tuples in a single tx. If a
# contract processes batch authorizations without ordering guarantees, an
# attacker can reorder or selectively replay authorizations.

_BATCH_AUTH_RE = re.compile(
    r"(authorization\s*\[\s*\]|authorizations\b|AuthorizationList"
    r"|batch.*auth|process.*auth.*list|for.*authorization)",
    re.IGNORECASE,
)
_AUTH_NONCE_CHECK_RE = re.compile(
    r"(auth\.nonce|authorization\.nonce|nonce\s*==\s*auth|verifyNonce)",
    re.IGNORECASE,
)


def detect_batch_auth_ordering(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    batch_match = _BATCH_AUTH_RE.search(source)
    if not batch_match:
        return findings

    has_nonce_check = _AUTH_NONCE_CHECK_RE.search(source)
    has_ordering = bool(re.search(r"require.*<.*nonce|require.*order|sequential", source, re.IGNORECASE))

    lines = source.splitlines()
    line_num = source[:batch_match.start()].count("\n") + 1

    if not has_nonce_check:
        findings.append(EIP7702Finding(
            check_id="AA7702-011",
            title="Batch authorization processing without nonce validation",
            severity="HIGH",
            description=(
                "Contract processes EIP-7702 authorization batches without validating "
                "per-authorization nonces. An attacker can: (1) Replay a previous "
                "authorization in a new batch. (2) Submit the same authorization "
                "multiple times in one batch. (3) Reorder authorizations to change "
                "the final delegation state (last-write-wins)."
            ),
            location=f"L{line_num}",
            cwe="CWE-294",
            recommendation=(
                "Validate each authorization's nonce against the account's current "
                "nonce. Increment the nonce atomically after processing. Reject "
                "duplicate authorizations within the same batch."
            ),
            confidence=0.80,
        ))
    elif not has_ordering:
        findings.append(EIP7702Finding(
            check_id="AA7702-011",
            title="Batch authorization ordering not enforced",
            severity="MEDIUM",
            description=(
                "Contract validates authorization nonces but does not enforce "
                "sequential ordering. In a batch with multiple authorizations for "
                "the same account, the final state depends on processing order, "
                "which may differ from the user's intent."
            ),
            location=f"L{line_num}",
            cwe="CWE-362",
            recommendation=(
                "Process authorizations in strict nonce order. If multiple "
                "authorizations target the same account, require they be sequential "
                "and process in nonce-ascending order."
            ),
            confidence=0.60,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-012: Nonce gap exploitation
# ─────────────────────────────────────────────────────────────────────────────
# EIP-7702 authorization nonces are separate from transaction nonces.
# After processing a 7702 authorization, the account's nonce increments.
# Contracts that rely on nonce for replay protection (e.g., meta-txs)
# may find their expected nonce invalidated by a 7702 authorization.

_NONCE_CHECK_RE = re.compile(
    r"(nonces\s*\[|_nonces\s*\[|nonce\s*==|nonce\s*>=|getNonce|useNonce)",
)
_META_TX_RE = re.compile(
    r"(executeMetaTransaction|MetaTransaction|relayCall|forwarder|Forwarder"
    r"|ERC2771|trustedForwarder|_msgSender\(\))",
    re.IGNORECASE,
)


def detect_nonce_gap(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_nonce = _NONCE_CHECK_RE.search(source)
    has_meta = _META_TX_RE.search(source)

    if not has_nonce:
        return findings

    has_permit = _PERMIT_RE.search(source)

    lines = source.splitlines()
    nonce_line = source[:has_nonce.start()].count("\n") + 1

    if has_meta:
        findings.append(EIP7702Finding(
            check_id="AA7702-012",
            title="Meta-transaction nonce vulnerable to EIP-7702 nonce gap",
            severity="HIGH",
            description=(
                "Contract implements meta-transactions with nonce-based replay "
                "protection. EIP-7702 authorization processing increments the "
                "account's nonce independently. If a user submits a 7702 delegation "
                "between signing a meta-tx and its execution, the nonce gap causes "
                "the meta-tx to revert (nonce mismatch) or worse — if nonce wraps, "
                "a previously used nonce becomes valid again."
            ),
            location=f"L{nonce_line}",
            cwe="CWE-294",
            recommendation=(
                "Use a nonce scheme tolerant of gaps (e.g., bitmap-based nonces "
                "like OpenZeppelin Nonces, or 2D nonces with separate channel). "
                "Do not assume sequential nonce increments."
            ),
            confidence=0.75,
        ))

    if has_permit:
        findings.append(EIP7702Finding(
            check_id="AA7702-012",
            title="Permit nonce may desync due to EIP-7702 authorization",
            severity="MEDIUM",
            description=(
                "Contract uses nonce-based replay protection for ERC-20 permit. "
                "EIP-7702 authorizations can increment the account nonce, causing "
                "previously signed permits to become invalid (nonce too low) or "
                "skipping nonces and making old permits valid again."
            ),
            location=f"L{nonce_line}",
            cwe="CWE-294",
            recommendation=(
                "Use a separate nonce space for permit signatures (not the account "
                "nonce). OpenZeppelin's Nonces contract tracks permit nonces "
                "independently from transaction nonces."
            ),
            confidence=0.65,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-013: Gas sponsorship griefing
# ─────────────────────────────────────────────────────────────────────────────
# A delegation target can consume arbitrary gas during the EOA's tx.
# If a protocol sponsors gas for delegated operations, a malicious
# delegation target can grief the sponsor by consuming maximum gas.

_GAS_LIMIT_RE = re.compile(
    r"(gasleft\s*\(\)|\.gas\s*\(|gas\s*:\s*\d|gasLimit|gasPrice|maxFeePerGas)",
)
_SPONSOR_RE = re.compile(
    r"(paymaster|sponsor|relay|gasless|meta.*tx|subsidiz|feeAbstract"
    r"|accountAbstract|AA.*entry|bundler|UserOperation)",
    re.IGNORECASE,
)
_DELEGATED_EXECUTION_RE = re.compile(
    r"(\.call\s*(?:\{|\()|delegatecall\s*\(|\bcall\s*\(\s*gas\s*\(\s*\)"
    r"|handleOps|userOp\.callData|PackedUserOperation)",
    re.IGNORECASE,
)


def detect_gas_griefing(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_sponsor = _SPONSOR_RE.search(source)

    if not (has_sponsor or _is_delegation_target(source)):
        return findings

    has_gas_limit = _GAS_LIMIT_RE.search(source)
    has_delegated_execution = _DELEGATED_EXECUTION_RE.search(source)
    lines = source.splitlines()

    if has_sponsor and has_delegated_execution and not has_gas_limit:
        line_num = source[:has_sponsor.start()].count("\n") + 1
        findings.append(EIP7702Finding(
            check_id="AA7702-013",
            title="Gas sponsorship without gas limit on delegated execution",
            severity="HIGH",
            description=(
                "Contract implements gas sponsorship/relay for delegated operations "
                "but does not enforce gas limits on the delegated code execution. "
                "A malicious delegation target can consume all provided gas in an "
                "infinite loop, griefing the gas sponsor. With EIP-7702, any EOA "
                "can delegate to a gas-draining contract and submit sponsored txs."
            ),
            location=f"L{line_num}",
            cwe="CWE-400",
            recommendation=(
                "Set explicit gas limits on calls to delegated EOAs: "
                "`addr.call{gas: MAX_GAS}(data)`. Implement per-account gas "
                "budgets and rate limiting. Validate the delegation target's "
                "code before sponsoring gas."
            ),
            confidence=0.75,
        ))

    if _is_delegation_target(source):
        has_unbounded_loop = bool(re.search(
            r"while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)|while\s*\(\s*1\s*\)",
            source,
        ))
        has_large_loop = bool(re.search(
            r"for\s*\([^)]*\.length\s*[;)]|while\s*\([^)]*<\s*\w+\.length\)",
            source,
        ))

        if (has_unbounded_loop or has_large_loop) and not has_gas_limit:
            findings.append(EIP7702Finding(
                check_id="AA7702-013",
                title="Delegation target contains unbounded loop — gas griefing risk",
                severity="MEDIUM",
                description=(
                    "This delegation target contains loops that iterate over "
                    "dynamic-length data. When an EOA delegates to this contract, "
                    "gas costs are borne by the tx sender (which may be a sponsor "
                    "or relayer). An attacker can grow the iterated data to consume "
                    "maximum gas."
                ),
                location="contract-level",
                cwe="CWE-400",
                recommendation=(
                    "Add explicit iteration bounds. Use pull patterns instead of "
                    "push (iterate-and-send). Implement gas checkpoints with "
                    "`gasleft()` guards."
                ),
                confidence=0.60,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-014: Value transfer to delegating EOA triggers code
# ─────────────────────────────────────────────────────────────────────────────
# Pre-7702: sending ETH to an EOA was a no-op (no code runs). Post-7702:
# sending ETH to a delegating EOA triggers the delegation target's
# receive()/fallback(). Contracts that send ETH to "known EOAs" with
# no expectation of callback are now vulnerable.

_ETH_TRANSFER_RE = re.compile(
    r"(\.transfer\s*\(|\.send\s*\(|\.call\s*\{\s*value\s*:|payable\s*\(\s*\w+\s*\)\.transfer)",
)
_STATE_AFTER_TRANSFER_RE = re.compile(
    r"(balances?\s*\[|_balances?\s*\[|totalSupply|\.sub\s*\(|[\-=]\s*amount|\-=)",
)


def detect_value_transfer_confusion(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []
    lines = source.splitlines()
    seen_fns: set[str] = set()

    for i, line in enumerate(lines):
        m = _ETH_TRANSFER_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue

        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue

        fn_start = i
        for j in range(i, max(i - 30, -1), -1):
            if re.match(r"^\s*function\s+", lines[j]):
                fn_start = j
                break

        fn_header = " ".join(lines[fn_start:min(fn_start + 3, len(lines))])
        if _REENTRANCY_GUARD_RE.search(fn_header):
            continue

        after_transfer = "\n".join(lines[i+1:min(i+5, len(lines))])
        state_after = _STATE_AFTER_TRANSFER_RE.search(after_transfer)

        if state_after:
            seen_fns.add(fn_name)
            findings.append(EIP7702Finding(
                check_id="AA7702-014",
                title=f"State update after ETH transfer in {fn_name}() — 7702 reentrancy",
                severity="HIGH",
                description=(
                    f"`{fn_name}()` modifies state AFTER sending ETH. Pre-EIP-7702, "
                    f"if the recipient was a known EOA, this was safe (no callback). "
                    f"Post-7702, any EOA can run arbitrary code on receive, re-entering "
                    f"`{fn_name}()` before the state update completes. Classic CEI "
                    f"(checks-effects-interactions) violation that was previously safe "
                    f"for EOA recipients."
                ),
                location=f"{fn_name}():L{i+1}",
                cwe="CWE-841",
                recommendation=(
                    "Follow checks-effects-interactions: update ALL state before the "
                    "ETH transfer. Add nonReentrant modifier. Never assume an address "
                    "cannot execute code on receive — after EIP-7702, all addresses can."
                ),
                confidence=0.85,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-015: selfdestruct in delegation target
# ─────────────────────────────────────────────────────────────────────────────
# If a delegation target contains selfdestruct, executing it in the EOA's
# context destroys the EOA's code designation. Post-Dencun, selfdestruct
# only sends ETH (doesn't destroy code) unless called in the creation tx.
# But the behavioral confusion still exists and older compiler versions
# may emit actual SELFDESTRUCT.

_SELFDESTRUCT_RE = re.compile(
    r"(selfdestruct\s*\(|suicide\s*\()",
)


def detect_selfdestruct_delegation(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    if not _is_delegation_target(source):
        return findings

    lines = source.splitlines()
    seen_fns: set[str] = set()

    for i, line in enumerate(lines):
        m = _SELFDESTRUCT_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue

        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue
        seen_fns.add(fn_name)

        findings.append(EIP7702Finding(
            check_id="AA7702-015",
            title=f"selfdestruct in delegation target {fn_name}() — EOA funds drain",
            severity="CRITICAL",
            description=(
                f"`{fn_name}()` contains selfdestruct in an EIP-7702 delegation target. "
                f"When called in the EOA's context, selfdestruct sends the EOA's "
                f"entire ETH balance to the specified address. Even post-Dencun "
                f"(where selfdestruct only transfers funds without destroying code "
                f"outside of creation tx), this drains the EOA's balance. A malicious "
                f"delegation target can use this as a one-call drain of all ETH."
            ),
            location=f"{fn_name}():L{i+1}",
            cwe="CWE-284",
            recommendation=(
                "Never include selfdestruct in EIP-7702 delegation targets. "
                "If emergency fund recovery is needed, implement a withdrawal "
                "pattern with proper authorization checks."
            ),
            confidence=0.92,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-016: ecrecover in delegation context
# ─────────────────────────────────────────────────────────────────────────────
# ecrecover assumes the recovered address is a dumb EOA that consciously
# signed a message. Post-7702, the signer might be a delegated EOA whose
# delegation code can sign arbitrary messages programmatically.

_ECRECOVER_RE = re.compile(
    r"ecrecover\s*\(|ECDSA\.recover\s*\(|SignatureChecker\.",
)
_SIGNATURE_VERIFY_RE = re.compile(
    r"function\s+\w*(verify|validate|check|recover)\w*\s*\(.*(?:signature|sig|v,\s*r,\s*s)",
    re.IGNORECASE,
)


def detect_ecrecover_delegation(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []
    lines = source.splitlines()
    seen_fns: set[str] = set()

    for i, line in enumerate(lines):
        m = _ECRECOVER_RE.search(line)
        if not m:
            continue
        if _is_in_comment_or_string(line, m.start()):
            continue

        fn_name = _enclosing_function(lines, i)
        if fn_name in seen_fns:
            continue

        context = "\n".join(lines[max(0, i-10):min(i+10, len(lines))])
        has_eip1271 = bool(re.search(r"isValidSignature|EIP1271|EIP-1271|1271|0x1626ba7e|SignatureChecker", context))
        # Safe-style dispatcher: `v == 0` routes the verification through
        # `checkContractSignature` (the ERC-1271 path) before falling
        # through to ecrecover for plain EOAs. The 1271 markers live in
        # a separate helper function and the ±10-line context window
        # above misses them. Widen to a file-level check for the
        # checkContractSignature helper and the `v == 0` discriminator.
        file_level_has_1271_dispatch = bool(
            re.search(r"checkContractSignature\s*\(", source)
            and re.search(r"\bv\s*==\s*0\b", source)
        )
        if file_level_has_1271_dispatch:
            has_eip1271 = True
        trusted_signer_check = bool(re.search(
            r"(?:recoveredSigner|signer)\s*!=\s*"
            r"(?:amlSigner|trustedSigner|oracleSigner|bridgeSigner|relayerSigner|backendSigner|validatorSigner|authorizedSigner)\b",
            context,
        ))

        if trusted_signer_check:
            continue

        if not has_eip1271:
            seen_fns.add(fn_name)
            findings.append(EIP7702Finding(
                check_id="AA7702-016",
                title=f"ecrecover without EIP-1271 fallback in {fn_name}() — 7702 blind spot",
                severity="MEDIUM",
                description=(
                    f"`{fn_name}()` uses ecrecover to verify signatures but does not "
                    f"support EIP-1271 (isValidSignature for contract wallets). "
                    f"Post-EIP-7702, EOAs can delegate to contracts, making them "
                    f"effectively smart wallets. Signature verification should support "
                    f"both ecrecover (for plain EOAs) and EIP-1271 (for delegated EOAs "
                    f"and smart wallets). Without this, delegated EOAs cannot interact "
                    f"with this contract's signature-gated functions."
                ),
                location=f"{fn_name}():L{i+1}",
                cwe="CWE-345",
                recommendation=(
                    "Use OpenZeppelin's SignatureChecker.isValidSignatureNow() which "
                    "tries ecrecover first, then falls back to EIP-1271 "
                    "isValidSignature(). This handles both plain EOAs and delegated "
                    "EOAs transparently."
                ),
                confidence=0.70,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-017: ERC-777 token hooks + delegation = new reentrancy
# ─────────────────────────────────────────────────────────────────────────────
# ERC-777 tokens call hooks (tokensReceived/tokensToSend) on recipients.
# Pre-7702, EOA recipients had no hook, so reentrancy via ERC-777 only
# worked against contracts. Post-7702, ANY address can have hooks via
# delegation, massively expanding the ERC-777 reentrancy surface.

_ERC777_RE = re.compile(
    r"(ERC777|tokensReceived|tokensToSend|IERC777Recipient|IERC777Sender"
    r"|_callTokensReceived|_callTokensToSend|registerRecipient)",
    re.IGNORECASE,
)
_HOOK_SKIP_EOA_RE = re.compile(
    r"(isContract|code\.length|extcodesize).*(?:skip|continue|return|&&)",
    re.IGNORECASE,
)


def detect_erc777_delegation(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_erc777 = _ERC777_RE.search(source)
    if not has_erc777:
        return findings

    lines = source.splitlines()

    for i, line in enumerate(lines):
        if _HOOK_SKIP_EOA_RE.search(line):
            fn_name = _enclosing_function(lines, i)
            findings.append(EIP7702Finding(
                check_id="AA7702-017",
                title=f"ERC-777 hook skipped for EOAs in {fn_name}() — 7702 bypass",
                severity="HIGH",
                description=(
                    f"`{fn_name}()` skips ERC-777 token hooks for addresses detected "
                    f"as EOAs (via isContract/code.length check). Post-EIP-7702, "
                    f"delegated EOAs have code and can implement tokensReceived/ "
                    f"tokensToSend hooks. Skipping hooks for 'EOAs' means delegated "
                    f"EOAs that registered ERC-777 hooks won't have them called, "
                    f"breaking the ERC-777 protocol. Conversely, if the check is "
                    f"inverted (only call hooks on contracts), delegated EOAs now "
                    f"get hooks called unexpectedly, enabling reentrancy."
                ),
                location=f"{fn_name}():L{i+1}",
                cwe="CWE-841",
                recommendation=(
                    "Remove the EOA/contract distinction from ERC-777 hook logic. "
                    "Always attempt to call hooks regardless of code.length. If the "
                    "address hasn't registered a hook, the call reverts or no-ops. "
                    "Add reentrancy guards to all token transfer functions."
                ),
                confidence=0.80,
            ))
            break

    if not findings:
        for i, line in enumerate(lines):
            if re.search(r"_callTokensReceived|_callTokensToSend", line):
                fn_name = _enclosing_function(lines, i)
                findings.append(EIP7702Finding(
                    check_id="AA7702-017",
                    title=f"ERC-777 hooks now callable on all addresses via EIP-7702",
                    severity="MEDIUM",
                    description=(
                        "Contract implements ERC-777 token hooks. Post-EIP-7702, the "
                        "set of addresses that can respond to hooks has expanded from "
                        "'only contracts' to 'any address with a delegation.' This "
                        "increases the reentrancy attack surface. Every ETH address is "
                        "now a potential hook implementer."
                    ),
                    location=f"{fn_name}():L{i+1}",
                    cwe="CWE-841",
                    recommendation=(
                        "Add ReentrancyGuard to all transfer functions. Review hook "
                        "call patterns for CEI compliance. Consider the expanded attack "
                        "surface when auditing reentrancy resistance."
                    ),
                    confidence=0.55,
                ))
                break

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-018: Approval front-running via delegated EOA
# ─────────────────────────────────────────────────────────────────────────────
# The classic approve+transferFrom race condition is amplified by EIP-7702.
# A delegated EOA can atomically front-run an approval change: in a single
# tx, the delegation code can (1) transferFrom the old allowance, (2) wait
# for the new approve() to land, (3) transferFrom the new allowance. This
# was theoretically possible before but required MEV bots; now it's
# programmable directly in the EOA's delegation code.

_APPROVE_RE = re.compile(
    r"function\s+approve\s*\(\s*address\s+\w+\s*,\s*uint\d*\s+\w+\s*\)[^;{]*\{",
    re.DOTALL,
)
_APPROVE_CALL_RE = re.compile(r"\.\s*approve\s*\(")
_INCREASE_ALLOWANCE_RE = re.compile(
    r"(increaseAllowance|decreaseAllowance|safeIncreaseAllowance)",
)


def detect_approval_frontrun(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    approve_def = _APPROVE_RE.search(source)
    approve_call = _APPROVE_CALL_RE.search(source)
    has_approve = approve_def or approve_call
    if not has_approve:
        return findings
    if approve_call and not approve_def:
        call_window = source[max(0, approve_call.start() - 80): approve_call.end() + 120]
        if re.search(r"\b[A-Z]\w*Lib\s*\.\s*approve\s*\(", call_window):
            return findings

    has_safe = _INCREASE_ALLOWANCE_RE.search(source)
    line_num = source[:has_approve.start()].count("\n") + 1
    fn_end = source.find("\n    }\n", has_approve.end())
    approve_body = source[has_approve.start(): fn_end if fn_end != -1 else len(source)]

    # A plain override that only delegates to OpenZeppelin ERC20's approve is
    # the standard ERC20 race, not a ChainEDR 7702-specific signal.
    if "super.approve" in approve_body and "allowance[" not in approve_body and "_approve(" not in approve_body:
        return findings

    if not has_safe:
        findings.append(EIP7702Finding(
            check_id="AA7702-018",
            title="approve() without increaseAllowance — EIP-7702 amplified front-run",
            severity="MEDIUM",
            description=(
                "Contract implements approve() but not increaseAllowance/"
                "decreaseAllowance. The classic ERC-20 approval race condition is "
                "amplified by EIP-7702: a spender with a delegated EOA can "
                "programmatically front-run approval changes. The delegation code "
                "monitors the mempool and atomically calls transferFrom(oldAllowance) "
                "before the new approve() lands, then transferFrom(newAllowance) "
                "after. This was previously MEV-bot territory; EIP-7702 makes it "
                "a built-in capability of any EOA."
            ),
            location=f"approve():L{line_num}",
            cwe="CWE-362",
            recommendation=(
                "Implement increaseAllowance()/decreaseAllowance() as the primary "
                "approval modification API. Alternatively, require approve() callers "
                "to first set allowance to 0 before setting a new value "
                "(OpenZeppelin SafeERC20.forceApprove pattern)."
            ),
            confidence=0.65,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-019: Hardcoded single relayer
# ─────────────────────────────────────────────────────────────────────────────
# EIP-7702 delegation contracts that only accept txs from one relayer address
# create a single point of failure. If that relayer goes offline, the account
# is bricked. Ethereum.org explicitly warns against this pattern.

_SINGLE_RELAYER_RE = re.compile(
    r"require\s*\(\s*msg\.sender\s*==\s*("
    r"relayer|RELAYER|trustedRelayer|_relayer|bundler|BUNDLER"
    r")\b",
)
_RELAYER_MAPPING_RE = re.compile(
    r"mapping\s*\([^)]*\)\s*(relayers|trustedRelayers|allowedRelayers|bundlers)",
)
_MULTI_RELAYER_RE = re.compile(
    r"(isRelayer|isAllowedRelayer|relayers\[|allowedRelayers\[|bundlers\[)",
)


def detect_hardcoded_relayer(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []
    lines = source.splitlines()

    has_single = _SINGLE_RELAYER_RE.search(source)
    if not has_single:
        return findings

    has_multi = _RELAYER_MAPPING_RE.search(source) or _MULTI_RELAYER_RE.search(source)
    if has_multi:
        return findings

    line_num = source[:has_single.start()].count("\n") + 1
    fn_name = _enclosing_function(lines, line_num - 1)

    findings.append(EIP7702Finding(
        check_id="AA7702-019",
        title=f"Hardcoded single relayer in {fn_name}() — account liveness risk",
        severity="MEDIUM",
        description=(
            f"Function `{fn_name}()` restricts execution to a single relayer "
            f"address. If this relayer goes offline, is censored, or its key is "
            f"lost, the delegated account becomes permanently bricked. "
            f"Ethereum's EIP-7702 guidance explicitly warns against hardcoding "
            f"a single trusted relayer."
        ),
        location=f"{fn_name}():L{line_num}",
        cwe="CWE-799",
        recommendation=(
            "Use a relayer allowlist (mapping or EnumerableSet) instead of a "
            "single address. Support ERC-4337 EntryPoint as a universal relayer "
            "fallback."
        ),
        confidence=0.70,
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-020: Missing ERC-7201 storage namespace
# ─────────────────────────────────────────────────────────────────────────────
# Delegation targets execute in the EOA's storage context. Without namespaced
# storage (ERC-7201), slot collisions occur when users switch between different
# delegation implementations. Slot 0 is especially dangerous.

# _ERC7201_RE is defined once at module top — used by both build_project_context and
# detect_missing_storage_namespace so both suppression and detection stay consistent.
_RAW_SLOT0_RE = re.compile(
    r"(storage\s+\w+\s+\w+\s*;|uint256\s+public\s+\w+\s*;|address\s+public\s+\w+\s*;)"
)
_IS_DELEGATION_TARGET_RE = re.compile(
    r"(EIP7702|EIP-7702|7702|AccountDelegation|DelegationTarget|"
    r"DelegationStorage|DelegateAccount|SmartAccount|AccountModule|WalletModule|"
    r"contract\s+\w*(?:Delegation|Delegate)\w*)"
)


def _is_storage_delegation_target(source: str) -> bool:
    return bool(
        (_is_delegation_target(source) or _IS_DELEGATION_TARGET_RE.search(source))
        and not _NOT_DELEGATION_TARGET_RE.search(source)
    )


def detect_missing_storage_namespace(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    if not _is_storage_delegation_target(source):
        return findings

    has_namespace = _ERC7201_RE.search(source)
    if has_namespace:
        return findings

    has_raw_storage = _RAW_SLOT0_RE.search(source)
    if not has_raw_storage:
        return findings

    line_num = source[:has_raw_storage.start()].count("\n") + 1

    findings.append(EIP7702Finding(
        check_id="AA7702-020",
        title="Delegation target uses raw storage without ERC-7201 namespace",
        severity="HIGH",
        description=(
            "This delegation target contract uses plain storage variables "
            "without ERC-7201 namespaced storage. When a delegating EOA "
            "switches between different implementations, raw slot 0-N storage "
            "persists and will be misinterpreted by the new code. "
            "This leads to storage corruption, type confusion, and potential "
            "asset loss."
        ),
        location=f"contract:L{line_num}",
        cwe="CWE-1260",
        recommendation=(
            "Use ERC-7201 namespaced storage: "
            "keccak256('eip7201:namespace.storage.MyContract') - 1. "
            "This isolates storage across different delegation targets."
        ),
        confidence=0.65,
    ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AA7702-021: Hardcoded EntryPoint version
# ─────────────────────────────────────────────────────────────────────────────
# ERC-4337 EntryPoint contracts are versioned. Delegation targets that hardcode
# v0.6 (0x5FF137...) won't work with v0.7 (0x0000000071727De22E5E9d8BAf0edAc6f37da032)
# or future versions, breaking account functionality.

_ENTRYPOINT_V06_RE = re.compile(
    r"0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
    re.IGNORECASE,
)
_ENTRYPOINT_V07_RE = re.compile(
    r"0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    re.IGNORECASE,
)
_ENTRYPOINT_CONFIGURABLE_RE = re.compile(
    r"(entryPoint\s*=|setEntryPoint|_entryPoint\s*=|constructor.*IEntryPoint)",
)


def detect_entrypoint_mismatch(source: str) -> list[EIP7702Finding]:
    findings: list[EIP7702Finding] = []

    has_v06 = _ENTRYPOINT_V06_RE.search(source)
    has_v07 = _ENTRYPOINT_V07_RE.search(source)

    if not has_v06 and not has_v07:
        return findings

    is_configurable = _ENTRYPOINT_CONFIGURABLE_RE.search(source)
    if is_configurable:
        return findings

    if has_v06 and not has_v07:
        line_num = source[:has_v06.start()].count("\n") + 1
        findings.append(EIP7702Finding(
            check_id="AA7702-021",
            title="Hardcoded EntryPoint v0.6 — incompatible with v0.7+",
            severity="MEDIUM",
            description=(
                "This delegation target hardcodes ERC-4337 EntryPoint v0.6 "
                "(0x5FF137D4...). EntryPoint v0.7 is now deployed at a "
                "different address (0x0000000071727De22E5E9d8BAf0edAc6f37da032). "
                "Users on v0.7 bundlers cannot use this account implementation. "
                "Future EntryPoint versions will require code updates or "
                "redeployment."
            ),
            location=f"contract:L{line_num}",
            cwe="CWE-1059",
            recommendation=(
                "Accept EntryPoint address as a constructor parameter or use a "
                "registry pattern. Support both v0.6 and v0.7 via interface "
                "compatibility."
            ),
            confidence=0.80,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class EIP7702Detector:
    """
    Static analyzer for EIP-7702 account-abstraction risk signals.

    Detects 21 focused classes introduced or made more relevant by the Pectra
    upgrade (May 2025). Findings are candidates until triaged or dynamically
    confirmed; this detector is not a production exploit oracle.
    """

    _ALL_CHECKS = [
        detect_tx_origin_eoa_bypass,        # AA7702-001
        detect_iscontract_bypass,           # AA7702-002
        detect_callback_reentrancy,         # AA7702-003
        detect_cross_chain_replay,          # AA7702-004
        detect_missing_revocation,          # AA7702-005
        detect_delegatecall_from_delegation, # AA7702-006
        detect_storage_collision,           # AA7702-007
        detect_initialization_race,         # AA7702-008
        detect_proxy_delegation_conflict,   # AA7702-009
        detect_permit_bypass,               # AA7702-010
        detect_batch_auth_ordering,         # AA7702-011
        detect_nonce_gap,                   # AA7702-012
        detect_gas_griefing,                # AA7702-013
        detect_value_transfer_confusion,    # AA7702-014
        detect_selfdestruct_delegation,     # AA7702-015
        detect_ecrecover_delegation,        # AA7702-016
        detect_erc777_delegation,           # AA7702-017
        detect_approval_frontrun,           # AA7702-018
        detect_hardcoded_relayer,           # AA7702-019
        detect_missing_storage_namespace,   # AA7702-020
        detect_entrypoint_mismatch,         # AA7702-021
    ]

    def is_affected(self, source: str) -> bool:
        """Quick check: does source contain patterns affected by EIP-7702?"""
        source = _strip_comments(source)
        # Aliased / state-flow patterns: a function that assigns tx.origin
        # or msg.sender into a variable AND performs at least one equality
        # comparison anywhere is a candidate for the alias-flow / state-flow
        # passes. Without this hook the multi-file scan_files screen drops
        # the file before check() ever runs.
        has_origin_assign = bool(
            _LOCAL_ASSIGN_TX_ORIGIN_RE.search(source)
            or _REASSIGN_TX_ORIGIN_RE.search(source)
        )
        has_sender_assign = bool(
            _LOCAL_ASSIGN_MSG_SENDER_RE.search(source)
            or _REASSIGN_MSG_SENDER_RE.search(source)
        )
        has_compare = bool(_COMPARE_RE.search(source))
        alias_candidate = (
            (has_origin_assign or has_sender_assign) and has_compare
        )
        return bool(
            _TX_ORIGIN_EOA_RE.search(source)
            or _ISCONTRACT_RE.search(source)
            or _DELEGATION_RE.search(source)
            or _SET_DELEGATION_RE.search(source)
            or _ONLY_EOA_MODIFIER_RE.search(source)
            or _ETH_TRANSFER_RE.search(source)
            or _PERMIT_RE.search(source)
            or _ECRECOVER_RE.search(source)
            or _ERC777_RE.search(source)
            or _APPROVE_RE.search(source)
            or _META_TX_RE.search(source)
            or _ERC1967_RE.search(source)
            or _SINGLE_RELAYER_RE.search(source)
            or _IS_DELEGATION_TARGET_RE.search(source)
            or _ENTRYPOINT_V06_RE.search(source)
            or alias_candidate
        )

    def check(self, source: str) -> list[EIP7702Finding]:
        """Run all 21 EIP-7702 checks on ONE file. Returns list of findings.

        NOTE: unchanged single-file API — the controlled benchmark calls this
        directly, so benchmark recall is preserved by construction. Universal
        FP suppression lives in scan_files (multi-file path) only.
        """
        clean = _strip_comments(source)
        findings: list[EIP7702Finding] = []
        for check_fn in self._ALL_CHECKS:
            findings.extend(check_fn(clean))
        return findings

    def scan_files(
        self,
        sources: dict,
        project_context: dict | None = None,
        deep: bool = False,
    ):
        """Multi-file project scan with universal FP suppression.

        sources: {filename: source_code}. Applies structural + context-aware
        filters that single-file regex cannot:
          - skip interface-only files (no implementation)
          - context-gate checks on a project-wide index (chain_id binding, etc.)
        Returns (list[(filename, EIP7702Finding)], project_context).
        """
        if project_context is None:
            project_context = build_project_context(sources, deep=deep)
        out: list[tuple[str, EIP7702Finding]] = []
        ast_interface_files = project_context.get("ast_interface_files") or set()
        for fname, content in sources.items():
            if fname in ast_interface_files or _is_interface_file(content):
                continue
            if not self.is_affected(content):
                continue
            for f in self.check(content):
                # Detector-set semantic_context (alias-flow,
                # cross-function-state-flow, etc.) carries the proof tag
                # the suppressor reads to skip IR-unreachability gating.
                # Merge into the project-level context instead of
                # overwriting, so both layers are visible.
                detector_set = dict(f.semantic_context or {})
                project_set = dict(
                    (project_context.get("semantic_files") or {}).get(fname)
                    or _semantic_context_for_source(content)
                )
                project_set.update(detector_set)
                f.semantic_context = project_set
                _attach_storage_ir_evidence(f, f.semantic_context)
                if _suppress_finding(content, f, project_context, fname=fname):
                    continue
                out.append((fname, f))
            sem = (project_context.get("semantic_files") or {}).get(fname) or {}
            has_semantic_paths = (
                sem.get("semantic_index")
                or (sem.get("semantic_ir") and sem.get("call_graph"))
            )
            if has_semantic_paths:
                for f in _semantic_path_findings_for_file(fname, sem, content):
                    f.semantic_context = dict(sem)
                    _attach_storage_ir_evidence(f, sem)
                    if _suppress_finding(content, f, project_context, fname=fname):
                        continue
                    out.append((fname, f))
        return out, project_context

    def check_selective(self, source: str, check_ids: list[str] | None = None) -> list[EIP7702Finding]:
        """Run selected checks only. If check_ids is None, runs all."""
        if check_ids is None:
            return self.check(source)

        clean = _strip_comments(source)
        findings: list[EIP7702Finding] = []
        id_to_fn = {f"AA7702-{i+1:03d}": fn for i, fn in enumerate(self._ALL_CHECKS)}

        for cid in check_ids:
            fn = id_to_fn.get(cid)
            if fn:
                findings.extend(fn(clean))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Plugin registration — wires 21 EIP-7702 checks into `chainedr scan`
# ─────────────────────────────────────────────────────────────────────────────

_PLUGIN_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


_PROOF_RECIPES = {
    "AA7702-001": {
        "readiness": "oracle_confirmable",
        "kind": "fork_oracle_behavior_flip",
        "objective": "show an EOA-gated path accepts a delegated EOA that now executes code",
        "auto_poc_status": "supported_by_confirm_demo",
    },
    "AA7702-002": {
        "readiness": "oracle_confirmable",
        "kind": "fork_oracle_behavior_flip",
        "objective": "show a code.length/isContract EOA assumption flips after delegation",
        "auto_poc_status": "supported_by_confirm_demo",
    },
    "AA7702-006": {
        "readiness": "fork_trace_candidate",
        "kind": "delegated_execution_trace",
        "objective": "trace delegatecall running through a delegated EOA storage/context",
        "auto_poc_status": "manual_target_calldata_needed",
    },
    "AA7702-007": {
        "readiness": "fork_storage_candidate",
        "kind": "delegated_storage_diff",
        "objective": "prove attacker-controlled delegated execution reads/writes unexpected EOA storage slots",
        "auto_poc_status": "manual_target_calldata_needed",
    },
    "AA7702-008": {
        "readiness": "fork_storage_candidate",
        "kind": "unauthorized_initializer_state_diff",
        "objective": "prove a non-owner can initialize or reinitialize delegated account state",
        "auto_poc_status": "manual_target_calldata_needed",
    },
    "AA7702-004": {
        "readiness": "semantic_static",
        "kind": "signature_domain_replay_review",
        "objective": "verify signatures bind chain id, verifying contract, and account/domain context",
        "auto_poc_status": "dynamic_replay_not_yet_automatic",
    },
    "AA7702-010": {
        "readiness": "semantic_static",
        "kind": "signature_domain_replay_review",
        "objective": "verify recovered signer, domain separator, nonce, and ERC-1271 fallback are all bound",
        "auto_poc_status": "dynamic_replay_not_yet_automatic",
    },
    "AA7702-011": {
        "readiness": "semantic_static",
        "kind": "userop_nonce_context_review",
        "objective": "verify replay protection is enforced by EntryPoint/UserOperation nonce context",
        "auto_poc_status": "userop_simulation_not_yet_automatic",
    },
    "AA7702-012": {
        "readiness": "semantic_static",
        "kind": "signature_nonce_context_review",
        "objective": "verify permit/meta-transaction nonces are independent from 7702 account nonce drift",
        "auto_poc_status": "dynamic_replay_not_yet_automatic",
    },
    "AA7702-013": {
        "readiness": "semantic_static",
        "kind": "userop_validation_review",
        "objective": "verify EntryPoint gas accounting and validation bounds delegated execution",
        "auto_poc_status": "userop_simulation_not_yet_automatic",
    },
    "AA7702-014": {
        "readiness": "fork_oracle_candidate",
        "kind": "value_flow_trace",
        "objective": "trace ETH sent to a delegated EOA and verify outbound value or stateful code execution",
        "auto_poc_status": "supported_by_bytecode_oracle",
    },
    "AA7702-016": {
        "readiness": "semantic_static",
        "kind": "signature_context_review",
        "objective": "verify the signature path binds chain, verifying contract, nonce, and ERC-1271 fallback",
        "auto_poc_status": "dynamic_replay_not_yet_automatic",
    },
    "AA7702-021": {
        "readiness": "semantic_static",
        "kind": "entrypoint_userop_context_review",
        "objective": "verify validateUserOp is bound to the intended EntryPoint and UserOperation hash",
        "auto_poc_status": "userop_simulation_not_yet_automatic",
    },
    "AA7702-018": {
        "readiness": "asset_oracle_candidate",
        "kind": "token_approval_or_sweep_diff",
        "objective": "prove delegated EOA approval or token movement with ERC-20/NFT balance diffs",
        "auto_poc_status": "supported_by_bytecode_oracle_primitives",
    },
}
_DYNAMIC_CONFIRMATION_SUPPORTED = frozenset({"AA7702-002"})


def _proof_status_for(check_id: str, recipe: dict) -> str:
    if check_id in _DYNAMIC_CONFIRMATION_SUPPORTED:
        return "CONFIRMABLE"
    if recipe.get("readiness") == "semantic_static":
        return "STATIC_CANDIDATE"
    return "STATIC_CANDIDATE"


def proof_metadata_for_check(check_id: str, semantic_context: dict | None = None) -> dict:
    """Reviewer-facing proof recipe for the focused 7702 path.

    This is intentionally not a claim that the finding is proven. It tells the
    main command what kind of evidence would turn the static signal into a
    bounty-grade argument.
    """
    recipe = _PROOF_RECIPES.get(check_id)
    if recipe is None:
        recipe = {
            "readiness": "semantic_static",
            "kind": "manual_review",
            "objective": "confirm exploitability from source context before claiming impact",
            "auto_poc_status": "not_automatic",
        }
    metadata = {
        "check_id": check_id,
        "status": "needs_dynamic_confirmation",
        "proof_status": _proof_status_for(check_id, recipe),
        "dynamic_confirmation_supported": check_id in _DYNAMIC_CONFIRMATION_SUPPORTED,
        "proof_ladder": [
            "static_signal",
            "semantic_gates",
            "dynamic_confirmation" if check_id in _DYNAMIC_CONFIRMATION_SUPPORTED else "manual_or_future_adapter",
            "evidence_bundle",
        ],
        **recipe,
    }
    if semantic_context:
        signature_model = semantic_context.get("signature_model") or {}
        userop_model = semantic_context.get("userop_model") or {}
        storage_model = semantic_context.get("storage_model") or {}
        semantic_ir = semantic_context.get("semantic_ir") or {}
        call_graph = semantic_context.get("call_graph") or {}
        ir_functions = semantic_ir.get("functions") or []
        metadata["semantic"] = {
            "analysis": semantic_context.get("analysis", "regex"),
            "sources": semantic_context.get("sources", []),
            "sinks": semantic_context.get("sinks", []),
            "has_access_guard": bool(semantic_context.get("has_access_guard")),
            "uses_erc1271": bool(semantic_context.get("uses_erc1271")),
            "uses_erc6492": bool(semantic_context.get("uses_erc6492")),
            "has_validate_userop": bool(semantic_context.get("has_validate_userop")),
            "complete_signature_model": bool(
                semantic_context.get("complete_signature_model")
            ),
            "signature_model": signature_model,
            "userop_model": userop_model,
        }
        if storage_model:
            metadata["semantic"]["storage_model"] = storage_model
        if semantic_ir:
            metadata["semantic"]["semantic_ir"] = {
                "analysis_depth": semantic_ir.get("analysis_depth"),
                "compiler_status": semantic_ir.get("compiler_status"),
                "summary": semantic_ir.get("summary") or {},
                "functions_with_facts": [
                    function.get("qualified_name")
                    for function in ir_functions
                    if (function.get("qualified_name") and _semantic_ir_function_has_facts(function))
                ],
            }
        if call_graph:
            metadata["semantic"]["call_graph"] = {
                "summary": call_graph.get("summary") or {},
                "unresolved_edges": call_graph.get("unresolved_edges") or [],
            }
    return metadata


def _semantic_ir_function_has_facts(function: dict) -> bool:
    fact_keys = (
        "storage_reads",
        "storage_writes",
        "external_calls",
        "delegatecalls",
        "value_transfers",
        "internal_calls",
        "auth_checks",
        "tx_origin_checks",
        "code_size_checks",
        "signature_checks",
        "calldata_parameters",
    )
    return any(function.get(key) for key in fact_keys)

try:
    from .detector_plugin import (
        Detector as _Detector,
        DetectorCategory as _DetCat,
        Finding as _Finding,
        ScanOptions as _ScanOpts,
        ScanResult as _ScanRes,
        Severity as _Sev,
        register_detector as _register,
    )
except ImportError:
    try:
        from detector_plugin import (  # type: ignore[no-redef]
            Detector as _Detector,
            DetectorCategory as _DetCat,
            Finding as _Finding,
            ScanOptions as _ScanOpts,
            ScanResult as _ScanRes,
            Severity as _Sev,
            register_detector as _register,
        )
    except ImportError:
        _Detector = None  # type: ignore[assignment,misc]


def _convert_finding(ef: EIP7702Finding, file_path: str) -> "_Finding":
    """Convert EIP7702Finding → normalized Finding for the plugin pipeline."""
    line = 0
    loc = ef.location
    if loc:
        m = re.search(r"[Ll](\d+)", loc)
        if m:
            line = int(m.group(1))

    return _Finding(
        detector="eip7702",
        rule_id=ef.check_id,
        severity=_Sev[_PLUGIN_SEV_MAP.get(ef.severity, "MEDIUM")],
        title=ef.title,
        description=ef.description,
        location=ef.location,
        file_path=file_path,
        line=line,
        category=_DetCat.EIP7702.value,
        cwe=ef.cwe,
        confidence=ef.confidence,
        exploitable=ef.severity == "CRITICAL",
        fix_suggestion=ef.recommendation,
        metadata={
            "sandbox_boundary": ef.sandbox_boundary,
            "bypass_class": ef.sandbox_bypass_class,
            "eip7702_specific": ef.eip7702_specific,
            "semantic_context": ef.semantic_context,
            "proof_recipe": ef.proof_metadata(),
        },
    )


if _Detector is not None:
    @_register
    class EIP7702PluginDetector(_Detector):
        """Registered plugin: 21 EIP-7702 delegation checks on .sol files."""

        name = "eip7702"
        capabilities = [_DetCat.EIP7702.value]

        def __init__(self) -> None:
            self._engine = EIP7702Detector()

        def discover(self, ctx) -> bool:
            return ctx.has_solidity

        def scan(self, ctx, opts: "_ScanOpts") -> "_ScanRes":
            result = _ScanRes(detector_name=self.name)
            findings: list[_Finding] = []
            sources: dict[str, str] = {}

            for sol_file in ctx.solidity_files:
                source = ctx.read_file(sol_file)
                result.files_scanned += 1
                result.lines_scanned += len(source.splitlines())
                rel = str(sol_file.relative_to(ctx.root)) if sol_file.is_relative_to(ctx.root) else sol_file.name
                sources[rel] = source

            deep = bool(getattr(opts, "deep", False) and getattr(opts, "use_ast", True))
            scanned, _ctx = self._engine.scan_files(sources, deep=deep)
            for rel, ef in scanned:
                findings.append(_convert_finding(ef, rel))

            try:
                try:
                    from .proof_adapters import attach_proof_adapters
                except ImportError:
                    from proof_adapters import attach_proof_adapters  # type: ignore
                attach_proof_adapters(findings)
            except Exception:
                pass

            result.findings = findings
            return result
