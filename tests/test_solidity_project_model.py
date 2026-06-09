import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from solidity_project_model import (  # noqa: E402
    build_project_model,
    build_standard_json_input,
    model_from_standard_output,
)


SOURCES = {
    "Base.sol": "contract Base { modifier onlyOwner() { _; } }",
    "Child.sol": """
import "./Base.sol";
contract Child is Base {
    function gated() external onlyOwner { require(tx.origin == msg.sender); }
}
""",
}


def test_standard_json_input_includes_sources_and_outputs():
    payload = build_standard_json_input(SOURCES, remappings=["@oz/=lib/openzeppelin-contracts/"])

    assert payload["language"] == "Solidity"
    assert payload["sources"]["Base.sol"]["content"].startswith("contract Base")
    assert payload["settings"]["remappings"] == ["@oz/=lib/openzeppelin-contracts/"]
    outputs = payload["settings"]["outputSelection"]["*"]
    assert "" in outputs
    assert "ast" in outputs[""]
    assert "storageLayout" in outputs["*"]


def test_standard_json_input_strips_windows_bom():
    payload = build_standard_json_input({"Gate.sol": "\ufeffpragma solidity ^0.8.20;"})

    assert payload["sources"]["Gate.sol"]["content"].startswith("pragma")


def test_model_from_standard_output_extracts_contract_function_modifier_and_source_ranges():
    output = {
        "sources": {
            "Base.sol": {
                "id": 0,
                "ast": {
                    "nodes": [
                        {
                            "nodeType": "ContractDefinition",
                            "name": "Base",
                            "contractKind": "contract",
                            "src": "0:45:0",
                            "baseContracts": [],
                            "nodes": [
                                {
                                    "nodeType": "ModifierDefinition",
                                    "name": "onlyOwner",
                                    "src": "16:25:0",
                                }
                            ],
                        }
                    ]
                },
            },
            "Child.sol": {
                "id": 1,
                "ast": {
                    "nodes": [
                        {
                            "nodeType": "ContractDefinition",
                            "name": "Child",
                            "contractKind": "contract",
                            "src": "21:95:1",
                            "baseContracts": [{"baseName": {"name": "Base"}}],
                            "nodes": [
                                {
                                    "nodeType": "FunctionDefinition",
                                    "name": "gated",
                                    "kind": "function",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "src": "50:64:1",
                                    "modifiers": [
                                        {"modifierName": {"name": "onlyOwner"}}
                                    ],
                                }
                            ],
                        }
                    ]
                },
            },
        },
        "contracts": {
            "Child.sol": {
                "Child": {
                    "abi": [{"type": "function", "name": "gated"}],
                    "storageLayout": {"storage": []},
                    "evm": {
                        "bytecode": {
                            "object": "60016002",
                            "sourceMap": "50:64:1:-:0",
                        }
                    },
                }
            }
        },
    }

    model = model_from_standard_output(SOURCES, output)

    assert model.compiler_status == "ok"
    assert model.analysis_depth == "standard_json_ast"
    assert model.summary() == {
        "source_files": 2,
        "contracts": 2,
        "functions": 1,
        "modifiers": 1,
        "inheritance_edges": 1,
    }
    child = next(contract for contract in model.contracts if contract.name == "Child")
    assert child.inherits == ["Base"]
    assert child.source.file == "Child.sol"
    assert child.functions[0].qualified_name == "Child.gated"
    assert child.functions[0].modifiers == ["onlyOwner"]
    assert child.functions[0].source.file == "Child.sol"
    assert child.abi == [{"type": "function", "name": "gated"}]
    assert child.storage_layout == {"storage": []}
    assert child.bytecode_length == 4
    assert child.bytecode_source_map == "50:64:1:-:0"


def test_build_project_model_marks_missing_solc_as_heuristic_fallback():
    model = build_project_model(SOURCES, solc="definitely-not-solc")

    assert model.compiler_status == "unavailable"
    assert model.analysis_depth == "heuristic_fallback"
    assert model.fallback_reason
    assert {contract.name for contract in model.contracts} == {"Base", "Child"}
    child = next(contract for contract in model.contracts if contract.name == "Child")
    assert child.inherits == ["Base"]
    assert child.functions[0].modifiers == ["onlyOwner"]
