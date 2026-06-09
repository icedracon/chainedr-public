"""IR-backed call graph facts for ChainEDR.

The first goal is explicitness: when a call target is resolved, record the edge;
when it is not, keep an uncertainty record instead of silently dropping it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

try:
    from .semantic_ir import build_semantic_ir
except ImportError:
    from semantic_ir import build_semantic_ir


@dataclass(frozen=True)
class CallGraphNode:
    file: str
    contract: str
    name: str
    qualified_name: str
    kind: str
    visibility: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "contract": self.contract,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "kind": self.kind,
            "visibility": self.visibility,
        }


@dataclass(frozen=True)
class CallGraphEdge:
    source: str
    target: str
    kind: str
    confidence: float
    uncertainty: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "detail": {key: self.detail[key] for key in sorted(self.detail)},
        }


@dataclass
class CallGraph:
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]

    @property
    def unresolved_edges(self) -> list[CallGraphEdge]:
        return [edge for edge in self.edges if edge.uncertainty]

    def summary(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "resolved_edges": len(self.edges) - len(self.unresolved_edges),
            "unresolved_edges": len(self.unresolved_edges),
            "modifier_edges": sum(1 for edge in self.edges if edge.kind == "modifier"),
            "internal_call_edges": sum(1 for edge in self.edges if edge.kind == "internal_call"),
            "dynamic_edges": sum(1 for edge in self.edges if edge.kind in {"external_call", "delegatecall"}),
        }

    def to_dict(self) -> dict:
        nodes = sorted(self.nodes, key=lambda node: node.qualified_name)
        edges = sorted(
            self.edges,
            key=lambda edge: (edge.source, edge.kind, edge.target, edge.uncertainty or ""),
        )
        return {
            "summary": self.summary(),
            "nodes": [node.to_dict() for node in nodes],
            "edges": [edge.to_dict() for edge in edges],
            "unresolved_edges": [
                edge.to_dict() for edge in edges if edge.uncertainty
            ],
        }


def build_call_graph(
    sources: dict[str, str],
    *,
    solc: str = "solc",
    timeout: int = 30,
) -> CallGraph:
    project = build_semantic_ir(sources, solc=solc, timeout=timeout)
    return call_graph_from_ir_functions([function.to_dict() for function in project.functions])


def call_graph_from_ir_functions(functions: Iterable[Mapping[str, Any]]) -> CallGraph:
    function_list = [dict(function) for function in functions]
    nodes = [_node_from_function(function) for function in function_list]
    by_qualified = {node.qualified_name: node for node in nodes}
    by_contract_name: dict[tuple[str, str], list[CallGraphNode]] = {}
    by_name: dict[str, list[CallGraphNode]] = {}
    for node in nodes:
        by_contract_name.setdefault((node.contract, node.name), []).append(node)
        by_name.setdefault(node.name, []).append(node)

    edges: list[CallGraphEdge] = []
    seen: set[tuple] = set()
    for function in function_list:
        source = str(function.get("qualified_name") or "")
        if not source or source not in by_qualified:
            continue
        contract = str(function.get("contract") or "")
        for modifier in function.get("modifiers") or []:
            edge = _resolved_or_uncertain_edge(
                source=source,
                call_name=str(modifier),
                kind="modifier",
                contract=contract,
                by_contract_name=by_contract_name,
                by_name=by_name,
                target_kind="modifier",
            )
            _append_edge(edges, seen, edge)
        for fact in function.get("internal_calls") or []:
            call_name = str((fact or {}).get("name") or "")
            if not call_name:
                continue
            edge = _resolved_or_uncertain_edge(
                source=source,
                call_name=call_name,
                kind="internal_call",
                contract=contract,
                by_contract_name=by_contract_name,
                by_name=by_name,
                target_kind=None,
            )
            _append_edge(edges, seen, edge)
        for fact in function.get("external_calls") or []:
            _append_edge(edges, seen, _dynamic_edge(source, fact, "external_call"))
        for fact in function.get("delegatecalls") or []:
            _append_edge(edges, seen, _dynamic_edge(source, fact, "delegatecall"))

    return CallGraph(nodes=nodes, edges=edges)


def _node_from_function(function: Mapping[str, Any]) -> CallGraphNode:
    return CallGraphNode(
        file=str(function.get("file") or ""),
        contract=str(function.get("contract") or ""),
        name=str(function.get("name") or ""),
        qualified_name=str(function.get("qualified_name") or ""),
        kind=str(function.get("kind") or "function"),
        visibility=str(function.get("visibility") or ""),
    )


def _resolved_or_uncertain_edge(
    *,
    source: str,
    call_name: str,
    kind: str,
    contract: str,
    by_contract_name: dict[tuple[str, str], list[CallGraphNode]],
    by_name: dict[str, list[CallGraphNode]],
    target_kind: Optional[str],
) -> CallGraphEdge:
    same_contract = _filter_kind(by_contract_name.get((contract, call_name), []), target_kind)
    global_matches = _filter_kind(by_name.get(call_name, []), target_kind)
    candidates = same_contract or global_matches
    if len(candidates) == 1:
        confidence = 0.95 if same_contract else 0.75
        return CallGraphEdge(
            source=source,
            target=candidates[0].qualified_name,
            kind=kind,
            confidence=confidence,
            detail={"resolution": "same_contract" if same_contract else "global_unique"},
        )
    if len(candidates) > 1:
        return CallGraphEdge(
            source=source,
            target=call_name,
            kind=kind,
            confidence=0.35,
            uncertainty="ambiguous_target",
            detail={"candidates": sorted(candidate.qualified_name for candidate in candidates)},
        )
    return CallGraphEdge(
        source=source,
        target=call_name,
        kind=kind,
        confidence=0.2,
        uncertainty="unresolved_target",
    )


def _filter_kind(nodes: list[CallGraphNode], kind: Optional[str]) -> list[CallGraphNode]:
    if kind is None:
        return [node for node in nodes if node.kind != "modifier"]
    return [node for node in nodes if node.kind == kind]


def _dynamic_edge(source: str, fact: Mapping[str, Any], kind: str) -> CallGraphEdge:
    return CallGraphEdge(
        source=source,
        target=str(fact.get("name") or "dynamic_target"),
        kind=kind,
        confidence=0.45,
        uncertainty="dynamic_target",
        detail={"fact_kind": str(fact.get("kind") or kind)},
    )


def _append_edge(edges: list[CallGraphEdge], seen: set[tuple], edge: CallGraphEdge) -> None:
    key = (
        edge.source,
        edge.target,
        edge.kind,
        edge.uncertainty,
        repr(sorted((edge.detail or {}).items())),
    )
    if key in seen:
        return
    seen.add(key)
    edges.append(edge)
