"""Compact semantic IR facts from Solidity standard JSON AST.

This is a narrow foundation for proof-grade detector inputs. It does not try to
replace Slither-style SSA yet; it extracts deterministic function-level facts
that can be snapshotted and fed into higher precision detectors over time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

try:
    from .solidity_project_model import SourceRange, compile_standard_json
except ImportError:
    from solidity_project_model import SourceRange, compile_standard_json


_FACT_BUCKETS = (
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

_CALL_SKIP = frozenset({
    "require", "assert", "revert", "emit", "return", "abi", "keccak256",
    "sha256", "ripemd160", "ecrecover", "addmod", "mulmod", "address",
    "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
    "int", "int8", "int16", "int32", "int64", "int128", "int256", "bool",
    "bytes", "bytes4", "bytes32", "string", "type",
})


@dataclass(frozen=True)
class IRFact:
    kind: str
    name: str
    source: Optional[SourceRange] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "source": self.source.to_dict() if self.source else None,
            "detail": {key: self.detail[key] for key in sorted(self.detail)},
        }


@dataclass
class FunctionIR:
    file: str
    contract: str
    name: str
    visibility: str
    mutability: str
    kind: str
    modifiers: List[str]
    source: Optional[SourceRange] = None
    storage_reads: List[IRFact] = field(default_factory=list)
    storage_writes: List[IRFact] = field(default_factory=list)
    external_calls: List[IRFact] = field(default_factory=list)
    delegatecalls: List[IRFact] = field(default_factory=list)
    value_transfers: List[IRFact] = field(default_factory=list)
    internal_calls: List[IRFact] = field(default_factory=list)
    auth_checks: List[IRFact] = field(default_factory=list)
    tx_origin_checks: List[IRFact] = field(default_factory=list)
    code_size_checks: List[IRFact] = field(default_factory=list)
    signature_checks: List[IRFact] = field(default_factory=list)
    calldata_parameters: List[IRFact] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return f"{self.contract}.{self.name}"

    def to_dict(self) -> dict:
        out = {
            "file": self.file,
            "contract": self.contract,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "visibility": self.visibility,
            "mutability": self.mutability,
            "kind": self.kind,
            "modifiers": self.modifiers,
            "source": self.source.to_dict() if self.source else None,
        }
        for bucket in _FACT_BUCKETS:
            out[bucket] = [fact.to_dict() for fact in getattr(self, bucket)]
        return out


@dataclass
class SemanticIRProject:
    sources: Dict[str, str]
    functions: List[FunctionIR]
    compiler_status: str
    analysis_depth: str
    compiler_errors: List[dict] = field(default_factory=list)
    fallback_reason: Optional[str] = None

    def summary(self) -> dict:
        facts_by_kind = {
            bucket: sum(len(getattr(fn, bucket)) for fn in self.functions)
            for bucket in _FACT_BUCKETS
        }
        return {
            "source_files": len(self.sources),
            "functions": len(self.functions),
            "facts": sum(facts_by_kind.values()),
            "facts_by_kind": facts_by_kind,
        }

    def to_dict(self) -> dict:
        return {
            "compiler_status": self.compiler_status,
            "analysis_depth": self.analysis_depth,
            "fallback_reason": self.fallback_reason,
            "compiler_errors": self.compiler_errors,
            "summary": self.summary(),
            "functions": [fn.to_dict() for fn in self.functions],
        }


def build_semantic_ir(
    sources: Dict[str, str],
    *,
    solc: str = "solc",
    timeout: int = 30,
    remappings: Optional[Iterable[str]] = None,
    evm_version: Optional[str] = None,
) -> SemanticIRProject:
    output, status, errors = compile_standard_json(
        sources,
        solc=solc,
        timeout=timeout,
        remappings=remappings,
        evm_version=evm_version,
    )
    if output and status == "ok":
        return semantic_ir_from_standard_output(sources, output, compiler_errors=errors)
    return SemanticIRProject(
        sources=sources,
        functions=[],
        compiler_status=status,
        analysis_depth="semantic_ir_unavailable",
        compiler_errors=errors,
        fallback_reason="solc unavailable or standard-json compilation failed",
    )


def semantic_ir_from_standard_output(
    sources: Dict[str, str],
    output: dict,
    *,
    compiler_errors: Optional[List[dict]] = None,
) -> SemanticIRProject:
    source_ids = {
        meta.get("id"): name
        for name, meta in output.get("sources", {}).items()
        if isinstance(meta, dict)
    }
    functions: List[FunctionIR] = []

    for source_name, meta in output.get("sources", {}).items():
        ast = meta.get("ast") or meta.get("AST")
        if not ast:
            continue
        for contract in _contract_nodes(ast):
            contract_name = contract.get("name", "")
            state_vars = _state_variables(contract)
            for node in contract.get("nodes", []):
                node_type = node.get("nodeType")
                if node_type == "FunctionDefinition":
                    fn_ir = FunctionIR(
                        file=source_name,
                        contract=contract_name,
                        name=node.get("name") or ("constructor" if node.get("kind") == "constructor" else ""),
                        visibility=node.get("visibility", ""),
                        mutability=node.get("stateMutability", ""),
                        kind=node.get("kind", "function"),
                        modifiers=_modifier_names(node.get("modifiers", [])),
                        source=_source_range(node.get("src"), source_ids, source_name),
                    )
                elif node_type == "ModifierDefinition":
                    fn_ir = FunctionIR(
                        file=source_name,
                        contract=contract_name,
                        name=node.get("name", ""),
                        visibility="modifier",
                        mutability="",
                        kind="modifier",
                        modifiers=[],
                        source=_source_range(node.get("src"), source_ids, source_name),
                    )
                else:
                    continue
                scanner = _FunctionFactScanner(fn_ir, state_vars, source_ids, source_name)
                scanner.add_parameters(node.get("parameters", {}))
                scanner.scan(node.get("body"))
                _dedupe_function_facts(fn_ir)
                functions.append(fn_ir)

    return SemanticIRProject(
        sources=sources,
        functions=functions,
        compiler_status="ok",
        analysis_depth="standard_json_ast_ir",
        compiler_errors=compiler_errors or [],
    )


class _FunctionFactScanner:
    def __init__(
        self,
        fn_ir: FunctionIR,
        state_vars: set[str],
        source_ids: dict,
        default_file: str,
    ) -> None:
        self.fn_ir = fn_ir
        self.state_vars = state_vars
        self.source_ids = source_ids
        self.default_file = default_file

    def add_parameters(self, parameters: dict) -> None:
        param_nodes = parameters.get("parameters", []) if isinstance(parameters, dict) else []
        for param in param_nodes:
            if param.get("storageLocation") != "calldata":
                continue
            name = param.get("name") or "<unnamed>"
            self._add(
                "calldata_parameters",
                "calldata_parameter",
                name,
                param,
                {"type": _type_name(param.get("typeName"))},
            )

    def scan(self, node: Any) -> None:
        self._walk(node)

    def _walk(self, node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                self._walk(item)
            return
        if not isinstance(node, dict):
            return

        node_type = node.get("nodeType")
        if node_type == "Assignment":
            for name in _identifier_names(node.get("leftHandSide")):
                if name in self.state_vars:
                    self._add("storage_writes", "storage_write", name, node.get("leftHandSide"))
            if node.get("operator") != "=":
                self._walk(node.get("leftHandSide"))
            self._walk(node.get("rightHandSide"))
            return

        if node_type == "Identifier":
            name = node.get("name")
            if name in self.state_vars:
                self._add("storage_reads", "storage_read", name, node)
            return

        if node_type == "BinaryOperation":
            text = _expr_name(node)
            if _is_tx_origin_check(text):
                self._add("tx_origin_checks", "tx_origin_check", "tx.origin==msg.sender", node)
                self._add("auth_checks", "auth_check", "tx_origin_eoa_gate", node)
            elif _looks_like_auth_check(text):
                self._add("auth_checks", "auth_check", text, node)
            if _is_code_size_check(text):
                self._add("code_size_checks", "code_size_check", text, node)
            self._walk(node.get("leftExpression"))
            self._walk(node.get("rightExpression"))
            return

        if node_type == "FunctionCall":
            self._scan_function_call(node)

        for child in node.values():
            if isinstance(child, (dict, list)):
                self._walk(child)

    def _scan_function_call(self, node: dict) -> None:
        expr = node.get("expression") or {}
        expr_name = _expr_name(expr)
        member = expr.get("memberName") if isinstance(expr, dict) else None

        if member in {"call", "staticcall"}:
            self._add("external_calls", "external_call", expr_name, node)
        elif member == "delegatecall":
            self._add("delegatecalls", "delegatecall", expr_name, node)
        elif member in {"send", "transfer"}:
            self._add("value_transfers", "value_transfer", expr_name, node)

        if expr_name == "ecrecover" or member == "isValidSignature":
            self._add("signature_checks", "signature_check", expr_name, node)
        if expr_name == "extcodesize":
            self._add("code_size_checks", "code_size_check", expr_name, node)

        if expr.get("nodeType") == "Identifier":
            name = expr.get("name", "")
            if name and name not in _CALL_SKIP and name not in self.state_vars:
                self._add("internal_calls", "internal_call", name, node)

        if expr_name in {"require", "assert"}:
            args = node.get("arguments", [])
            condition = _expr_name(args[0]) if args else ""
            if _looks_like_auth_check(condition):
                self._add("auth_checks", "auth_check", condition, node)

    def _add(
        self,
        bucket: str,
        kind: str,
        name: str,
        node: Optional[dict],
        detail: Optional[dict] = None,
    ) -> None:
        getattr(self.fn_ir, bucket).append(
            IRFact(
                kind=kind,
                name=name,
                source=_source_range((node or {}).get("src"), self.source_ids, self.default_file),
                detail=detail or {},
            )
        )


def _contract_nodes(ast: dict) -> list[dict]:
    return [
        node for node in ast.get("nodes", [])
        if isinstance(node, dict) and node.get("nodeType") == "ContractDefinition"
    ]


def _state_variables(contract: dict) -> set[str]:
    names: set[str] = set()
    for node in contract.get("nodes", []):
        if node.get("nodeType") == "VariableDeclaration" and node.get("stateVariable"):
            name = node.get("name")
            if name:
                names.add(name)
    return names


def _dedupe_function_facts(fn_ir: FunctionIR) -> None:
    for bucket in _FACT_BUCKETS:
        seen: set[tuple] = set()
        deduped: list[IRFact] = []
        for fact in getattr(fn_ir, bucket):
            source_key = None
            if fact.source:
                source_key = (fact.source.file, fact.source.start, fact.source.length)
            key = (fact.kind, fact.name, source_key, tuple(sorted(fact.detail.items())))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(fact)
        setattr(fn_ir, bucket, deduped)


def _source_range(raw: Optional[str], source_ids: dict, default_file: str) -> Optional[SourceRange]:
    if not raw:
        return None
    parts = raw.split(":")
    if len(parts) < 3:
        return None
    try:
        start = int(parts[0])
        length = int(parts[1])
        file_id = int(parts[2])
    except ValueError:
        return None
    return SourceRange(file=source_ids.get(file_id, default_file), start=start, length=length)


def _modifier_names(modifiers: list) -> List[str]:
    names: List[str] = []
    for modifier in modifiers:
        node = modifier.get("modifierName", {})
        name = node.get("name") or node.get("memberName") or node.get("namePath")
        if name:
            names.append(name)
    return names


def _identifier_names(node: Any) -> set[str]:
    if isinstance(node, list):
        out: set[str] = set()
        for item in node:
            out.update(_identifier_names(item))
        return out
    if not isinstance(node, dict):
        return set()
    if node.get("nodeType") == "Identifier" and node.get("name"):
        return {node["name"]}
    out: set[str] = set()
    for child in node.values():
        if isinstance(child, (dict, list)):
            out.update(_identifier_names(child))
    return out


def _expr_name(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    node_type = node.get("nodeType")
    if node_type == "Identifier":
        return node.get("name", "")
    if node_type == "MemberAccess":
        base = _expr_name(node.get("expression"))
        member = node.get("memberName", "")
        return f"{base}.{member}" if base else member
    if node_type == "FunctionCall":
        return _expr_name(node.get("expression"))
    if node_type == "BinaryOperation":
        left = _expr_name(node.get("leftExpression"))
        right = _expr_name(node.get("rightExpression"))
        return f"{left} {node.get('operator', '')} {right}".strip()
    if node_type == "UnaryOperation":
        return _expr_name(node.get("subExpression"))
    if node_type == "IndexAccess":
        return _expr_name(node.get("baseExpression"))
    if node_type == "Literal":
        return str(node.get("value") or node.get("hexValue") or "")
    return ""


def _type_name(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    if node.get("name"):
        return str(node["name"])
    if node.get("typeIdentifier"):
        return str(node["typeIdentifier"])
    if node.get("nodeType") == "ArrayTypeName":
        return f"{_type_name(node.get('baseType'))}[]"
    return node.get("nodeType", "")


def _is_tx_origin_check(text: str) -> bool:
    compact = text.replace(" ", "")
    return "tx.origin==msg.sender" in compact or "msg.sender==tx.origin" in compact


def _is_code_size_check(text: str) -> bool:
    return ".code.length" in text or "extcodesize" in text


def _looks_like_auth_check(text: str) -> bool:
    if _is_tx_origin_check(text):
        return True
    lowered = text.lower()
    return "msg.sender" in text and any(
        signal in lowered
        for signal in ("owner", "admin", "guardian", "operator", "role", "authorized")
    )
