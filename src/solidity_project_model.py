"""Compiler-backed Solidity project model.

This is the first narrow step toward a canonical ChainEDR project model. It can
consume solc standard JSON output, and falls back to the existing dependency-free
semantic index when solc is unavailable or cannot compile the project.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    from .semantic_index import build_semantic_index
except ImportError:
    from semantic_index import build_semantic_index


@dataclass(frozen=True)
class SourceRange:
    file: str
    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + self.length

    def to_dict(self) -> dict:
        return {"file": self.file, "start": self.start, "length": self.length}


@dataclass
class FunctionModel:
    contract: str
    name: str
    visibility: str
    mutability: str
    modifiers: List[str]
    kind: str
    source: Optional[SourceRange] = None

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
            "kind": self.kind,
            "source": self.source.to_dict() if self.source else None,
        }


@dataclass
class ContractModel:
    file: str
    name: str
    kind: str
    inherits: List[str]
    functions: List[FunctionModel] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    source: Optional[SourceRange] = None
    abi: List[dict] = field(default_factory=list)
    storage_layout: dict = field(default_factory=dict)
    bytecode_length: int = 0
    bytecode_source_map: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "name": self.name,
            "kind": self.kind,
            "inherits": self.inherits,
            "modifiers": self.modifiers,
            "source": self.source.to_dict() if self.source else None,
            "abi": self.abi,
            "storage_layout": self.storage_layout,
            "bytecode_length": self.bytecode_length,
            "bytecode_source_map": self.bytecode_source_map,
            "functions": [fn.to_dict() for fn in self.functions],
        }


@dataclass
class SolidityProjectModel:
    sources: Dict[str, str]
    contracts: List[ContractModel]
    compiler_status: str
    analysis_depth: str
    compiler_errors: List[dict] = field(default_factory=list)
    fallback_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "compiler_status": self.compiler_status,
            "analysis_depth": self.analysis_depth,
            "fallback_reason": self.fallback_reason,
            "compiler_errors": self.compiler_errors,
            "summary": self.summary(),
            "contracts": [contract.to_dict() for contract in self.contracts],
        }

    def summary(self) -> dict:
        functions = [fn for contract in self.contracts for fn in contract.functions]
        return {
            "source_files": len(self.sources),
            "contracts": len(self.contracts),
            "functions": len(functions),
            "modifiers": sum(len(contract.modifiers) for contract in self.contracts),
            "inheritance_edges": sum(len(contract.inherits) for contract in self.contracts),
        }


def build_standard_json_input(
    sources: Dict[str, str],
    *,
    remappings: Optional[Iterable[str]] = None,
    evm_version: Optional[str] = None,
) -> dict:
    settings: dict = {
        "outputSelection": {
            "*": {
                "*": [
                    "abi",
                    "evm.bytecode.object",
                    "evm.bytecode.sourceMap",
                    "storageLayout",
                ],
                "": ["ast"],
            }
        }
    }
    if remappings:
        settings["remappings"] = list(remappings)
    if evm_version:
        settings["evmVersion"] = evm_version
    return {
        "language": "Solidity",
        "sources": {
            name: {"content": _normalize_source_content(content)}
            for name, content in sorted(sources.items())
        },
        "settings": settings,
    }


def compile_standard_json(
    sources: Dict[str, str],
    *,
    solc: str = "solc",
    timeout: int = 30,
    remappings: Optional[Iterable[str]] = None,
    evm_version: Optional[str] = None,
) -> tuple[Optional[dict], str, List[dict]]:
    if not (shutil.which(solc) or Path(solc).exists()):
        return None, "unavailable", []
    payload = build_standard_json_input(
        sources,
        remappings=remappings,
        evm_version=evm_version,
    )
    try:
        proc = subprocess.run(
            [solc, "--standard-json"],
            input=json.dumps(payload).encode(),
            capture_output=True,
            timeout=timeout,
        )
    except Exception as exc:
        return None, "failed", [{"severity": "error", "message": str(exc)}]

    errors: List[dict] = []
    try:
        output = json.loads(proc.stdout.decode() or "{}")
        errors = [
            {
                "severity": err.get("severity", "unknown"),
                "type": err.get("type", "unknown"),
                "message": err.get("message", ""),
                "sourceLocation": err.get("sourceLocation"),
            }
            for err in output.get("errors", [])
        ]
    except Exception as exc:
        return None, "failed", [{"severity": "error", "message": f"invalid solc JSON: {exc}"}]

    blocking = any(err.get("severity") == "error" for err in errors)
    if proc.returncode != 0 or blocking:
        return output, "failed", errors
    return output, "ok", errors


def build_project_model(
    sources: Dict[str, str],
    *,
    solc: str = "solc",
    timeout: int = 30,
    remappings: Optional[Iterable[str]] = None,
    evm_version: Optional[str] = None,
) -> SolidityProjectModel:
    output, status, errors = compile_standard_json(
        sources,
        solc=solc,
        timeout=timeout,
        remappings=remappings,
        evm_version=evm_version,
    )
    if output and status == "ok":
        return model_from_standard_output(sources, output, compiler_errors=errors)
    return model_from_semantic_fallback(
        sources,
        compiler_status=status,
        compiler_errors=errors,
        fallback_reason="solc unavailable or standard-json compilation failed",
    )


def model_from_standard_output(
    sources: Dict[str, str],
    output: dict,
    *,
    compiler_errors: Optional[List[dict]] = None,
) -> SolidityProjectModel:
    source_ids = {
        meta.get("id"): name
        for name, meta in output.get("sources", {}).items()
        if isinstance(meta, dict)
    }
    contracts: List[ContractModel] = []
    for source_name, meta in output.get("sources", {}).items():
        ast = meta.get("ast") or meta.get("AST")
        if not ast:
            continue
        for node in ast.get("nodes", []):
            if node.get("nodeType") != "ContractDefinition":
                continue
            contract = ContractModel(
                file=source_name,
                name=node.get("name", ""),
                kind=node.get("contractKind", "contract"),
                inherits=_base_names(node.get("baseContracts", [])),
                source=_source_range(node.get("src"), source_ids, source_name),
            )
            _attach_contract_outputs(contract, output, source_name)
            for child in node.get("nodes", []):
                node_type = child.get("nodeType")
                if node_type == "ModifierDefinition":
                    contract.modifiers.append(child.get("name", ""))
                elif node_type == "FunctionDefinition":
                    contract.functions.append(_function_model(contract.name, child, source_ids, source_name))
            contracts.append(contract)
    return SolidityProjectModel(
        sources=sources,
        contracts=contracts,
        compiler_status="ok",
        analysis_depth="standard_json_ast",
        compiler_errors=compiler_errors or [],
    )


def model_from_semantic_fallback(
    sources: Dict[str, str],
    *,
    compiler_status: str,
    compiler_errors: Optional[List[dict]] = None,
    fallback_reason: Optional[str] = None,
) -> SolidityProjectModel:
    index = build_semantic_index(sources)
    contracts: List[ContractModel] = []
    for semantic in index.contracts:
        functions = [
            FunctionModel(
                contract=semantic.name,
                name=fn.name,
                visibility=fn.visibility,
                mutability=fn.mutability,
                modifiers=fn.modifiers,
                kind="constructor" if fn.name == "constructor" else "function",
            )
            for fn in semantic.functions
        ]
        contracts.append(
            ContractModel(
                file=semantic.file,
                name=semantic.name,
                kind=semantic.kind,
                inherits=semantic.inherits,
                functions=functions,
                modifiers=semantic.modifiers,
            )
        )
    return SolidityProjectModel(
        sources=sources,
        contracts=contracts,
        compiler_status=compiler_status,
        analysis_depth="heuristic_fallback",
        compiler_errors=compiler_errors or [],
        fallback_reason=fallback_reason,
    )


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
    return SourceRange(
        file=source_ids.get(file_id, default_file),
        start=start,
        length=length,
    )


def _normalize_source_content(content: str) -> str:
    return content.lstrip("\ufeff")


def _base_names(base_contracts: list) -> List[str]:
    out: List[str] = []
    for base in base_contracts:
        name_node = base.get("baseName", {})
        name = name_node.get("name") or name_node.get("namePath")
        if name:
            out.append(name)
    return out


def _function_model(contract: str, node: dict, source_ids: dict, default_file: str) -> FunctionModel:
    name = node.get("name") or ("constructor" if node.get("kind") == "constructor" else "")
    return FunctionModel(
        contract=contract,
        name=name,
        visibility=node.get("visibility", ""),
        mutability=node.get("stateMutability", ""),
        modifiers=_modifier_names(node.get("modifiers", [])),
        kind=node.get("kind", "function"),
        source=_source_range(node.get("src"), source_ids, default_file),
    )


def _attach_contract_outputs(contract: ContractModel, output: dict, source_name: str) -> None:
    compiled = (
        output.get("contracts", {})
        .get(source_name, {})
        .get(contract.name, {})
    )
    if not compiled:
        return
    contract.abi = compiled.get("abi") or []
    contract.storage_layout = compiled.get("storageLayout") or {}
    bytecode = compiled.get("evm", {}).get("bytecode", {})
    object_hex = bytecode.get("object") or ""
    contract.bytecode_length = len(object_hex) // 2 if object_hex else 0
    contract.bytecode_source_map = bytecode.get("sourceMap")


def _modifier_names(modifiers: list) -> List[str]:
    names: List[str] = []
    for modifier in modifiers:
        node = modifier.get("modifierName", {})
        name = node.get("name") or node.get("memberName") or node.get("namePath")
        if name:
            names.append(name)
    return names
