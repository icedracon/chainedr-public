"""Project-level semantic index for Solidity sources.

This is the first production hardening layer above regex checks. It uses the
existing brace-aware Solidity scope extractor to build reusable facts about:

- contracts and inheritance edges;
- function modifiers and modifier definition locations;
- internal call graph edges;
- initializer/reinitializer surfaces;
- proxy-like implementation and delegatecall surfaces.

It is intentionally best-effort and dependency-free. It does not replace the
solc AST bridge; it gives the scanner useful semantic facts even when solc or
imports are unavailable in CI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set

try:
    from .ast_scope import ContractInfo, FunctionInfo, _find_matching_brace, extract_contracts
except ImportError:
    from ast_scope import ContractInfo, FunctionInfo, _find_matching_brace, extract_contracts


_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_MODIFIER_DEF_RE = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*\{", re.S)
_OVERRIDE_RE = re.compile(r"\boverride\s*(?:\(([^)]*)\))?")

_CALL_SKIP = frozenset({
    "if", "for", "while", "require", "assert", "revert", "emit", "return",
    "abi", "keccak256", "sha256", "ripemd160", "ecrecover", "addmod",
    "mulmod", "this", "super", "delete", "new", "type", "unchecked",
    "address", "uint", "uint8", "uint16", "uint32", "uint64", "uint128",
    "uint256", "int", "int8", "int16", "int32", "int64", "int128",
    "int256", "bool", "bytes", "bytes4", "bytes32", "string",
})

_ACL_MODIFIERS = frozenset({
    "onlyOwner", "onlyAdmin", "onlyRole", "onlyCoreRole", "onlyGovernor",
    "onlyGuardian", "requiresAuth", "requireAuth", "authorized", "restricted",
})

_TX_ORIGIN_EOA_RE = re.compile(
    r"(tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin)",
)
_CODE_LENGTH_EOA_RE = re.compile(
    r"(\.isContract\s*\(|\.code\.length\s*(==|!=|>|<)\s*0"
    r"|extcodesize\s*\(\s*\w+\s*\)\s*(==|!=|>|<)\s*0"
    r"|codesize\s*:=\s*extcodesize)",
)
_EOA_NAMED_MODIFIER_RE = re.compile(r"^(onlyEOA|noContract|isEOA|notContract)$", re.I)

_PROXY_SIGNALS = {
    "delegatecall": re.compile(r"\bdelegatecall\s*\(", re.I),
    "erc1967_slot": re.compile(r"360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", re.I),
    "upgrade_function": re.compile(r"\b(upgradeTo|upgradeToAndCall|setImplementation)\s*\(", re.I),
    "implementation_function": re.compile(r"\b(_implementation|implementation)\s*\(", re.I),
    "fallback": re.compile(r"\b(fallback|receive)\s*\(", re.I),
    "uups": re.compile(r"\b(UUPS|proxiableUUID|ERC1967Upgrade)\b", re.I),
}
_UPGRADE_FUNCTION_RE = re.compile(r"^(upgradeTo|upgradeToAndCall|setImplementation|_setImplementation)$")
_DELEGATECALL_BODY_RE = re.compile(r"\bdelegatecall\s*\(", re.I)
_STATE_WRITE_RE_TEMPLATE = r"(?:^|[^\w.]){name}\s*(?:=|\+=|-=|\*=|/=|\+\+|--|\[)"
_OWNER_LIKE_STATE_RE = re.compile(r"(owner|admin|manager|controller|guardian)", re.I)
_DELEGATION_KEYWORD_RE = re.compile(
    r"(7702|EIP7702|EIP-7702|setCode|executeAs|delegatedExec|"
    r"AccountDelegation|DelegationTarget|DelegationStorage|DelegateAccount|SmartAccount)",
    re.I,
)
_DELEGATION_ENTRYPOINT_RE = re.compile(
    r"^(executeAs|delegatedExec|executeDelegated|setCode|setDelegation|installDelegation|execute)$",
    re.I,
)
_INFRASTRUCTURE_CONTRACT_RE = re.compile(
    r"(Enforcer|Module|Factory|Manager|Registry|Resolver|Hook|Guard|Paymaster)$",
)
_ERC7201_SOURCE_RE = re.compile(
    r"(erc7201|eip7201|custom:storage-location|keccak256\(['\"]eip7201:"
    r"|\.slot\s*:=|StorageSlot\.|_STORAGE_(SLOT|LOCATION))",
    re.I,
)
_STATE_DECL_RE = re.compile(
    r"^\s*(?P<type>mapping\s*\([^;]+\)(?:\s*\[\])?|[A-Za-z_]\w*"
    r"(?:\s+payable)?(?:\s*\[\])?)\s+"
    r"(?P<attrs>(?:(?:public|private|internal|constant|immutable|override|transient)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=|;)",
    re.S,
)


@dataclass
class StateVariableSemantic:
    contract: str
    name: str
    type_name: str
    visibility: str
    slot_index: int | None
    line: int
    is_constant: bool
    is_immutable: bool
    is_owner_like: bool

    @property
    def qualified_name(self) -> str:
        return f"{self.contract}.{self.name}"

    @property
    def is_storage_backed(self) -> bool:
        return not (self.is_constant or self.is_immutable)

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "type": self.type_name,
            "visibility": self.visibility,
            "slot_index": self.slot_index,
            "line": self.line,
            "is_constant": self.is_constant,
            "is_immutable": self.is_immutable,
            "is_storage_backed": self.is_storage_backed,
            "is_owner_like": self.is_owner_like,
        }


@dataclass
class ModifierSemantic:
    contract: str
    name: str
    guard_signals: List[str]

    @property
    def qualified_name(self) -> str:
        return f"{self.contract}.{self.name}"

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "guard_signals": self.guard_signals,
        }


@dataclass
class FunctionSemantic:
    contract: str
    name: str
    visibility: str
    mutability: str
    modifiers: List[str]
    resolved_modifiers: List[str]
    direct_calls: List[str]
    direct_call_targets: List[str]
    reachable_internal_calls: List[str]
    modifier_guard_signals: List[str]
    modifier_guard_sources: List[str]
    uses_delegatecall: bool
    state_writes: List[str]
    initializer_guard_signals: List[str]
    is_entrypoint: bool
    is_access_controlled: bool
    is_initializer: bool
    overrides: bool
    override_bases: List[str]

    @property
    def qualified_name(self) -> str:
        return f"{self.contract}.{self.name}"

    def to_dict(self) -> dict:
        return {
            "contract": self.contract,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "visibility": self.visibility,
            "mutability": self.mutability,
            "modifiers": self.modifiers,
            "resolved_modifiers": self.resolved_modifiers,
            "direct_calls": self.direct_calls,
            "direct_call_targets": self.direct_call_targets,
            "reachable_internal_calls": self.reachable_internal_calls,
            "modifier_guard_signals": self.modifier_guard_signals,
            "modifier_guard_sources": self.modifier_guard_sources,
            "uses_delegatecall": self.uses_delegatecall,
            "state_writes": self.state_writes,
            "initializer_guard_signals": self.initializer_guard_signals,
            "is_entrypoint": self.is_entrypoint,
            "is_access_controlled": self.is_access_controlled,
            "is_initializer": self.is_initializer,
            "overrides": self.overrides,
            "override_bases": self.override_bases,
        }


@dataclass
class ContractSemantic:
    file: str
    name: str
    kind: str
    inherits: List[str]
    linearized_bases: List[str]
    modifiers: List[str]
    modifier_definitions: List[ModifierSemantic] = field(default_factory=list)
    state_variables: List[StateVariableSemantic] = field(default_factory=list)
    functions: List[FunctionSemantic] = field(default_factory=list)
    uses_erc7201: bool = False
    proxy_signals: List[str] = field(default_factory=list)
    proxy_model: dict = field(default_factory=dict)
    delegation_model: dict = field(default_factory=dict)

    @property
    def is_proxy_like(self) -> bool:
        return bool(self.proxy_signals or self.proxy_model.get("is_proxy_like"))

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "name": self.name,
            "kind": self.kind,
            "inherits": self.inherits,
            "linearized_bases": self.linearized_bases,
            "modifiers": self.modifiers,
            "modifier_definitions": [m.to_dict() for m in self.modifier_definitions],
            "state_variables": [v.to_dict() for v in self.state_variables],
            "uses_erc7201": self.uses_erc7201,
            "is_proxy_like": self.is_proxy_like,
            "proxy_signals": self.proxy_signals,
            "proxy_model": self.proxy_model,
            "delegation_model": self.delegation_model,
            "functions": [f.to_dict() for f in self.functions],
        }


class ProjectSemanticIndex:
    def __init__(self, contracts: List[ContractSemantic]) -> None:
        self.contracts = contracts
        self.by_contract = {c.name: c for c in contracts}
        self.by_file: Dict[str, List[ContractSemantic]] = {}
        for contract in contracts:
            self.by_file.setdefault(contract.file, []).append(contract)

    def to_dict(self) -> dict:
        return {
            "files": {
                fname: [contract.to_dict() for contract in contracts]
                for fname, contracts in sorted(self.by_file.items())
            },
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        functions = [f for c in self.contracts for f in c.functions]
        return {
            "contracts": len(self.contracts),
            "functions": len(functions),
            "inheritance_edges": self.inheritance_edges(),
            "call_graph_edges": self.call_graph_edges(),
            "proxy_contracts": sorted(c.name for c in self.contracts if c.is_proxy_like),
            "proxy_models": {
                c.name: c.proxy_model for c in self.contracts if c.proxy_model
            },
            "delegation_contracts": sorted(
                c.name for c in self.contracts
                if c.delegation_model.get("is_delegation_like")
            ),
            "delegation_models": {
                c.name: c.delegation_model
                for c in self.contracts
                if c.delegation_model
            },
            "initializer_functions": sorted(
                f.qualified_name for f in functions if f.is_initializer
            ),
            "access_controlled_entrypoints": sorted(
                f.qualified_name for f in functions if f.is_entrypoint and f.is_access_controlled
            ),
        }

    def file_summary(self, fname: str) -> dict:
        contracts = self.by_file.get(fname, [])
        functions = [f for c in contracts for f in c.functions]
        return {
            "contracts": [c.name for c in contracts],
            "inheritance_edges": [
                [c.name, base] for c in contracts for base in c.inherits
            ],
            "modifiers": sorted({m for c in contracts for m in c.modifiers}),
            "modifier_definitions": [
                m.to_dict()
                for c in contracts
                for m in c.modifier_definitions
            ],
            "state_variables": [
                v.to_dict()
                for c in contracts
                for v in c.state_variables
            ],
            "functions": [f.to_dict() for f in functions],
            "call_graph_edges": [
                [f.qualified_name, target]
                for f in functions
                for target in f.direct_call_targets
            ],
            "reachable_internal_calls": {
                f.qualified_name: f.reachable_internal_calls
                for f in functions
                if f.reachable_internal_calls
            },
            "has_proxy_like_contract": any(c.is_proxy_like for c in contracts),
            "proxy_contracts": sorted(c.name for c in contracts if c.is_proxy_like),
            "proxy_models": {
                c.name: c.proxy_model for c in contracts if c.proxy_model
            },
            "delegation_contracts": sorted(
                c.name for c in contracts
                if c.delegation_model.get("is_delegation_like")
            ),
            "delegation_models": {
                c.name: c.delegation_model
                for c in contracts
                if c.delegation_model
            },
            "initializer_functions": sorted(
                f.qualified_name for f in functions if f.is_initializer
            ),
            "overrides": sorted(f.qualified_name for f in functions if f.overrides),
        }

    def inheritance_edges(self) -> List[List[str]]:
        return sorted([c.name, base] for c in self.contracts for base in c.inherits)

    def call_graph_edges(self) -> List[List[str]]:
        edges = []
        for contract in self.contracts:
            for fn in contract.functions:
                for target in fn.direct_call_targets:
                    edges.append([fn.qualified_name, target])
        return sorted(edges)


def build_semantic_index(sources: Dict[str, str]) -> ProjectSemanticIndex:
    raw_contracts: Dict[str, tuple[str, ContractInfo]] = {}
    modifiers_by_contract: Dict[str, Dict[str, str]] = {}

    for fname, source in sources.items():
        for contract in extract_contracts(source):
            raw_contracts[contract.name] = (fname, contract)
            modifiers_by_contract[contract.name] = _extract_modifier_defs(contract.source)

    linearized = {
        name: _linearized_bases(name, raw_contracts)
        for name in raw_contracts
    }

    contract_semantics: Dict[str, ContractSemantic] = {}
    function_lookup: Dict[str, FunctionSemantic] = {}

    for name, (fname, contract) in raw_contracts.items():
        semantic = ContractSemantic(
            file=fname,
            name=name,
            kind=contract.kind,
            inherits=contract.inherits,
            linearized_bases=linearized[name],
            modifiers=sorted(modifiers_by_contract.get(name, {})),
            modifier_definitions=[
                ModifierSemantic(
                    contract=name,
                    name=mod_name,
                    guard_signals=_modifier_guard_signals(mod_name, mod_body),
                )
                for mod_name, mod_body in sorted(modifiers_by_contract.get(name, {}).items())
            ],
            state_variables=_extract_state_variables(name, contract.source),
            uses_erc7201=bool(_ERC7201_SOURCE_RE.search(contract.source)),
            proxy_signals=_proxy_signals(contract.source),
        )
        contract_semantics[name] = semantic

    for name, (_fname, contract) in raw_contracts.items():
        semantic = contract_semantics[name]
        callable_names = _callable_names(name, raw_contracts, linearized)
        state_var_names = [
            var.name for var in semantic.state_variables
            if var.is_storage_backed
        ]
        for fn in contract.functions:
            direct_calls = _direct_internal_calls(fn.body, callable_names)
            header = _function_header(contract.source, fn)
            overrides, override_bases = _override_info(header)
            resolved_targets = [
                _resolve_call_target(name, call, raw_contracts, linearized)
                for call in direct_calls
            ]
            resolved_targets = [target for target in resolved_targets if target]
            resolved_modifiers = _resolve_modifiers(
                name,
                fn.modifiers,
                modifiers_by_contract,
                linearized,
            )
            modifier_signals, modifier_sources = _modifier_guard_context(
                resolved_modifiers,
                modifiers_by_contract,
            )
            fs = FunctionSemantic(
                contract=name,
                name=fn.name,
                visibility=fn.visibility,
                mutability=fn.mutability,
                modifiers=fn.modifiers,
                resolved_modifiers=resolved_modifiers,
                direct_calls=direct_calls,
                direct_call_targets=sorted(set(resolved_targets)),
                reachable_internal_calls=[],
                modifier_guard_signals=modifier_signals,
                modifier_guard_sources=modifier_sources,
                uses_delegatecall=bool(_DELEGATECALL_BODY_RE.search(fn.body)),
                state_writes=_state_writes(fn.body, state_var_names),
                initializer_guard_signals=_initializer_guard_signals(fn),
                is_entrypoint=fn.visibility in {"public", "external"},
                is_access_controlled=_has_access_control(fn),
                is_initializer=_is_initializer(fn),
                overrides=overrides,
                override_bases=override_bases,
            )
            semantic.functions.append(fs)
            function_lookup[fs.qualified_name] = fs

    for fn in function_lookup.values():
        fn.reachable_internal_calls = _reachable_internal_calls(fn, function_lookup)

    for contract in contract_semantics.values():
        contract.proxy_model = _build_proxy_model(contract)
        contract.delegation_model = _build_delegation_model(contract)

    return ProjectSemanticIndex(list(contract_semantics.values()))


def _extract_state_variables(contract_name: str, contract_source: str) -> List[StateVariableSemantic]:
    variables: List[StateVariableSemantic] = []
    slot_index = 0
    for statement, line in _top_level_statements(contract_source):
        statement = re.sub(r"/\*.*?\*/|//[^\n]*", "", statement, flags=re.S).strip()
        if not statement:
            continue
        if re.match(r"^(using|event|error|function|modifier|constructor|struct|enum)\b", statement):
            continue
        match = _STATE_DECL_RE.match(statement)
        if not match:
            continue
        attrs = set(re.findall(r"\b(public|private|internal|constant|immutable|transient)\b", match.group("attrs")))
        is_constant = "constant" in attrs
        is_immutable = "immutable" in attrs
        storage_slot = None if is_constant or is_immutable else slot_index
        if storage_slot is not None:
            slot_index += 1
        visibility = next(
            (item for item in ("public", "private", "internal") if item in attrs),
            "default",
        )
        name = match.group("name")
        variables.append(StateVariableSemantic(
            contract=contract_name,
            name=name,
            type_name=" ".join(match.group("type").split()),
            visibility=visibility,
            slot_index=storage_slot,
            line=line,
            is_constant=is_constant,
            is_immutable=is_immutable,
            is_owner_like=bool(_OWNER_LIKE_STATE_RE.search(name)),
        ))
    return variables


def _top_level_statements(source: str) -> List[tuple[str, int]]:
    statements: List[tuple[str, int]] = []
    start = 0
    i = 0
    n = len(source)
    while i < n:
        char = source[i]
        if char == "{":
            close = _find_matching_brace(source, i)
            if close == -1:
                break
            i = close + 1
            start = i
            continue
        if char == ";":
            statement = source[start:i + 1]
            line = source[:start].count("\n") + 1
            statements.append((statement, line))
            start = i + 1
        i += 1
    return statements


def _extract_modifier_defs(contract_source: str) -> Dict[str, str]:
    modifiers: Dict[str, str] = {}
    for match in _MODIFIER_DEF_RE.finditer(contract_source):
        open_pos = match.end() - 1
        close_pos = _find_matching_brace(contract_source, open_pos)
        if close_pos != -1:
            modifiers[match.group(1)] = contract_source[open_pos + 1:close_pos]
    return modifiers


def _linearized_bases(
    contract_name: str,
    raw_contracts: Dict[str, tuple[str, ContractInfo]],
    seen: tuple[str, ...] = (),
) -> List[str]:
    if contract_name in seen:
        return []
    contract = raw_contracts.get(contract_name, (None, None))[1]
    if contract is None:
        return []
    out: List[str] = []
    for base in contract.inherits:
        if base in out:
            continue
        out.append(base)
        out.extend(_linearized_bases(base, raw_contracts, (*seen, contract_name)))
    return _dedupe(out)


def _callable_names(
    contract_name: str,
    raw_contracts: Dict[str, tuple[str, ContractInfo]],
    linearized: Dict[str, List[str]],
) -> Set[str]:
    names: Set[str] = set()
    for cname in [contract_name, *linearized.get(contract_name, [])]:
        contract = raw_contracts.get(cname, (None, None))[1]
        if contract:
            names.update(fn.name for fn in contract.functions)
    return names


def _direct_internal_calls(body: str, callable_names: Set[str]) -> List[str]:
    calls = []
    for name in _CALL_RE.findall(body):
        if name in _CALL_SKIP:
            continue
        if name in callable_names:
            calls.append(name)
    return _dedupe(calls)


def _resolve_call_target(
    contract_name: str,
    call_name: str,
    raw_contracts: Dict[str, tuple[str, ContractInfo]],
    linearized: Dict[str, List[str]],
) -> str:
    for cname in [contract_name, *linearized.get(contract_name, [])]:
        contract = raw_contracts.get(cname, (None, None))[1]
        if contract and any(fn.name == call_name for fn in contract.functions):
            return f"{cname}.{call_name}"
    return ""


def _resolve_modifiers(
    contract_name: str,
    modifiers: Iterable[str],
    modifiers_by_contract: Dict[str, Dict[str, str]],
    linearized: Dict[str, List[str]],
) -> List[str]:
    resolved: List[str] = []
    search_order = [contract_name, *linearized.get(contract_name, [])]
    for modifier in modifiers:
        target = ""
        for cname in search_order:
            if modifier in modifiers_by_contract.get(cname, {}):
                target = f"{cname}.{modifier}"
                break
        resolved.append(target or modifier)
    return resolved


def _modifier_guard_signals(modifier_name: str, body: str) -> List[str]:
    signals: List[str] = []
    if _TX_ORIGIN_EOA_RE.search(body):
        signals.append("tx_origin_eoa")
    if _CODE_LENGTH_EOA_RE.search(body):
        signals.append("code_length_eoa_gate")
    if _EOA_NAMED_MODIFIER_RE.search(modifier_name):
        signals.append("eoa_named_modifier")
    return _dedupe(signals)


def _modifier_guard_context(
    resolved_modifiers: Iterable[str],
    modifiers_by_contract: Dict[str, Dict[str, str]],
) -> tuple[List[str], List[str]]:
    signals: List[str] = []
    sources: List[str] = []
    for resolved in resolved_modifiers:
        if "." not in resolved:
            if _EOA_NAMED_MODIFIER_RE.search(resolved):
                signals.append("eoa_named_modifier")
                sources.append(resolved)
            continue
        contract_name, modifier_name = resolved.split(".", 1)
        body = modifiers_by_contract.get(contract_name, {}).get(modifier_name, "")
        modifier_signals = _modifier_guard_signals(modifier_name, body)
        if modifier_signals:
            signals.extend(modifier_signals)
            sources.append(resolved)
    return _dedupe(signals), _dedupe(sources)


def _state_writes(body: str, state_var_names: Iterable[str]) -> List[str]:
    writes: List[str] = []
    for name in state_var_names:
        pattern = re.compile(
            _STATE_WRITE_RE_TEMPLATE.format(name=re.escape(name)),
            re.I | re.M,
        )
        if pattern.search(body):
            writes.append(name)
    if re.search(r"\bsstore\s*\(", body, re.I) or ".slot :=" in body:
        writes.append("assembly_storage")
    return _dedupe(writes)


def _initializer_guard_signals(fn: FunctionInfo) -> List[str]:
    signals: List[str] = []
    mods = {m.lower() for m in fn.modifiers}
    if "initializer" in mods:
        signals.append("initializer_modifier")
    if "reinitializer" in mods:
        signals.append("reinitializer_modifier")
    if re.search(r"\breinitializer\s*\(", " ".join(fn.modifiers), re.I):
        signals.append("reinitializer_modifier")
    if re.search(r"\brequire\s*\([^;]*(?:!_?initialized|initialized\s*==\s*0)", fn.body, re.I | re.S):
        signals.append("one_time_initialized_require")
    if re.search(r"\b_?initialized\s*=\s*(?:true|1)", fn.body, re.I):
        signals.append("sets_initialized_flag")
    if re.search(r"\b_disableInitializers\s*\(", fn.body):
        signals.append("disables_initializers")
    return _dedupe(signals)


def _reachable_internal_calls(
    fn: FunctionSemantic,
    function_lookup: Dict[str, FunctionSemantic],
) -> List[str]:
    seen: Set[str] = set()

    def visit(target: str) -> None:
        if target in seen:
            return
        target_fn = function_lookup.get(target)
        if not target_fn:
            return
        if target_fn.visibility in {"internal", "private"}:
            seen.add(target)
        for next_target in target_fn.direct_call_targets:
            visit(next_target)

    for target in fn.direct_call_targets:
        visit(target)
    return sorted(seen)


def _function_header(contract_source: str, fn: FunctionInfo) -> str:
    open_pos = contract_source.find("{", fn.start, fn.end + 1)
    if open_pos == -1:
        return contract_source[fn.start:fn.end]
    return contract_source[fn.start:open_pos]


def _override_info(header: str) -> tuple[bool, List[str]]:
    match = _OVERRIDE_RE.search(header)
    if not match:
        return False, []
    bases = [
        item.strip()
        for item in (match.group(1) or "").split(",")
        if item.strip()
    ]
    return True, bases


def _has_access_control(fn: FunctionInfo) -> bool:
    if fn.visibility in {"internal", "private"}:
        return True
    if any(mod in _ACL_MODIFIERS or mod.lower().startswith("only") for mod in fn.modifiers):
        return True
    return fn.has_regex_guard(r"require\s*\([^;]*(owner|admin|role|auth|governor|guardian)")


def _is_initializer(fn: FunctionInfo) -> bool:
    mods = {m.lower() for m in fn.modifiers}
    return (
        fn.name.lower() in {"initialize", "init", "reinitialize"}
        or "initializer" in mods
        or "reinitializer" in mods
    )


def _proxy_signals(contract_source: str) -> List[str]:
    return sorted(
        name for name, pattern in _PROXY_SIGNALS.items()
        if pattern.search(contract_source)
    )


def _build_proxy_model(contract: ContractSemantic) -> dict:
    upgrade_functions = [
        fn for fn in contract.functions
        if _UPGRADE_FUNCTION_RE.match(fn.name)
    ]
    fallback_delegatecall = (
        "fallback" in contract.proxy_signals and "delegatecall" in contract.proxy_signals
    )
    erc1967_slots = ["implementation"] if "erc1967_slot" in contract.proxy_signals else []
    if not (contract.proxy_signals or upgrade_functions):
        return {}

    initializer_functions = [
        fn.qualified_name for fn in contract.functions if fn.is_initializer
    ]
    unprotected_upgrade_functions = [
        fn.qualified_name for fn in upgrade_functions
        if fn.is_entrypoint and not fn.is_access_controlled
    ]
    risk_flags: List[str] = []
    if fallback_delegatecall:
        risk_flags.append("fallback_delegatecall")
    if unprotected_upgrade_functions:
        risk_flags.append("unprotected_upgrade_function")
    if initializer_functions and fallback_delegatecall:
        risk_flags.append("initializer_on_proxy_like_contract")
    if "uups" in contract.proxy_signals:
        risk_flags.append("uups_surface")

    return {
        "is_proxy_like": bool(contract.proxy_signals or fallback_delegatecall or upgrade_functions),
        "signals": contract.proxy_signals,
        "fallback_delegatecall": fallback_delegatecall,
        "erc1967_slots": erc1967_slots,
        "upgrade_functions": [fn.qualified_name for fn in upgrade_functions],
        "unprotected_upgrade_functions": unprotected_upgrade_functions,
        "initializer_functions": initializer_functions,
        "risk_flags": _dedupe(risk_flags),
    }


def _build_delegation_model(contract: ContractSemantic) -> dict:
    signals = _delegation_signals(contract)
    is_delegation_like = bool(signals) and not _INFRASTRUCTURE_CONTRACT_RE.search(contract.name)
    delegatecall_functions = [
        fn.qualified_name for fn in contract.functions if fn.uses_delegatecall
    ]
    external_delegatecall_functions = [
        fn.qualified_name for fn in contract.functions
        if fn.uses_delegatecall and fn.is_entrypoint
    ]
    entrypoints = [
        fn.qualified_name for fn in contract.functions
        if fn.is_entrypoint and _DELEGATION_ENTRYPOINT_RE.match(fn.name)
    ]
    raw_state_vars = [
        var for var in contract.state_variables if var.is_storage_backed
    ]
    owner_like_state_vars = [
        var.qualified_name for var in raw_state_vars if var.is_owner_like
    ]
    initializer_functions = [
        fn.qualified_name for fn in contract.functions if fn.is_initializer
    ]
    unguarded_initializer_functions = [
        fn.qualified_name for fn in contract.functions
        if fn.is_initializer
        and fn.is_entrypoint
        and not fn.initializer_guard_signals
    ]
    stateful_entrypoints = [
        fn.qualified_name for fn in contract.functions
        if fn.is_entrypoint and fn.state_writes
    ]
    proxy_risk_flags = list(contract.proxy_model.get("risk_flags") or [])
    if contract.proxy_model.get("is_proxy_like"):
        proxy_risk_flags.append("proxy_like_delegation_target")
    if contract.proxy_model.get("unprotected_upgrade_functions"):
        proxy_risk_flags.append("unprotected_upgrade_on_delegation_target")

    if not is_delegation_like:
        return {}

    return {
        "is_delegation_like": is_delegation_like,
        "signals": _dedupe(signals),
        "entrypoints": entrypoints,
        "delegatecall_functions": delegatecall_functions,
        "external_delegatecall_functions": external_delegatecall_functions,
        "state_variables": [var.to_dict() for var in contract.state_variables],
        "raw_storage_variable_count": len(raw_state_vars),
        "owner_like_state_variables": owner_like_state_vars,
        "stateful_entrypoints": stateful_entrypoints,
        "initializer_functions": initializer_functions,
        "unguarded_initializer_functions": unguarded_initializer_functions,
        "uses_erc7201": contract.uses_erc7201,
        "proxy_risk_flags": _dedupe(proxy_risk_flags),
        "proof_focus": _delegation_proof_focus(
            external_delegatecall_functions,
            raw_state_vars,
            unguarded_initializer_functions,
            proxy_risk_flags,
        ),
    }


def _delegation_signals(contract: ContractSemantic) -> List[str]:
    signals: List[str] = []
    if _DELEGATION_KEYWORD_RE.search(contract.name):
        signals.append("contract_name")
    if any(_DELEGATION_KEYWORD_RE.search(base) for base in contract.inherits):
        signals.append("inheritance")
    if any(_DELEGATION_ENTRYPOINT_RE.match(fn.name) for fn in contract.functions):
        signals.append("delegation_entrypoint")
    if any(fn.uses_delegatecall for fn in contract.functions) and _DELEGATION_KEYWORD_RE.search(contract.name):
        signals.append("delegated_delegatecall")
    if any("delegation" in var.name.lower() for var in contract.state_variables):
        signals.append("delegation_state")
    if any("SmartAccount" in base or "Account" in base for base in contract.inherits):
        signals.append("account_inheritance")
    return _dedupe(signals)


def _delegation_proof_focus(
    delegatecall_functions: List[str],
    raw_state_vars: List[StateVariableSemantic],
    unguarded_initializer_functions: List[str],
    proxy_risk_flags: List[str],
) -> List[str]:
    focus: List[str] = []
    if delegatecall_functions:
        focus.append("trace nested delegatecall under delegated EOA context")
    if raw_state_vars:
        focus.append("diff raw EOA storage slots before and after delegated calls")
    if unguarded_initializer_functions:
        focus.append("prove unauthorized initialize/reinitialize state mutation")
    if proxy_risk_flags:
        focus.append("inspect proxy implementation/admin slots under EOA storage")
    return focus


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out
