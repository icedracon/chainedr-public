import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from call_graph import call_graph_from_ir_functions  # noqa: E402


def _function(
    name: str,
    *,
    kind: str = "function",
    modifiers: list[str] | None = None,
    internal_calls: list[str] | None = None,
    external_calls: list[str] | None = None,
    delegatecalls: list[str] | None = None,
) -> dict:
    return {
        "file": "Wallet.sol",
        "contract": "Wallet",
        "name": name,
        "qualified_name": f"Wallet.{name}",
        "visibility": "external" if name == "execute" else "internal",
        "kind": kind,
        "modifiers": modifiers or [],
        "internal_calls": [
            {"kind": "internal_call", "name": call}
            for call in (internal_calls or [])
        ],
        "external_calls": [
            {"kind": "external_call", "name": call}
            for call in (external_calls or [])
        ],
        "delegatecalls": [
            {"kind": "delegatecall", "name": call}
            for call in (delegatecalls or [])
        ],
    }


def test_call_graph_resolves_modifiers_and_internal_calls():
    graph = call_graph_from_ir_functions([
        _function("execute", modifiers=["onlyHuman"], internal_calls=["_beforeExecute"]),
        _function("onlyHuman", kind="modifier"),
        _function("_beforeExecute", internal_calls=["_authorize"]),
        _function("_authorize"),
    ])
    payload = graph.to_dict()
    edge_pairs = {
        (edge["source"], edge["target"], edge["kind"], edge["uncertainty"])
        for edge in payload["edges"]
    }

    assert ("Wallet.execute", "Wallet.onlyHuman", "modifier", None) in edge_pairs
    assert ("Wallet.execute", "Wallet._beforeExecute", "internal_call", None) in edge_pairs
    assert ("Wallet._beforeExecute", "Wallet._authorize", "internal_call", None) in edge_pairs
    assert payload["summary"]["resolved_edges"] == 3
    assert payload["summary"]["unresolved_edges"] == 0


def test_call_graph_keeps_unresolved_and_dynamic_edges():
    graph = call_graph_from_ir_functions([
        _function(
            "execute",
            internal_calls=["_missing"],
            external_calls=["target.call"],
            delegatecalls=["impl.delegatecall"],
        )
    ])
    payload = graph.to_dict()
    unresolved = {
        (edge["target"], edge["kind"], edge["uncertainty"])
        for edge in payload["unresolved_edges"]
    }

    assert ("_missing", "internal_call", "unresolved_target") in unresolved
    assert ("target.call", "external_call", "dynamic_target") in unresolved
    assert ("impl.delegatecall", "delegatecall", "dynamic_target") in unresolved
    assert payload["summary"]["dynamic_edges"] == 2
