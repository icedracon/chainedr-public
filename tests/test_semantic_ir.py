import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from semantic_ir import build_semantic_ir, semantic_ir_from_standard_output  # noqa: E402


SOURCES = {"Wallet.sol": "contract Wallet {}"}


def _identifier(name: str, src: str = "1:1:0") -> dict:
    return {"nodeType": "Identifier", "name": name, "src": src}


def _member(base: dict, member: str, src: str = "1:1:0") -> dict:
    return {
        "nodeType": "MemberAccess",
        "expression": base,
        "memberName": member,
        "src": src,
    }


def _call(expression: dict, args: list | None = None, src: str = "1:1:0") -> dict:
    return {
        "nodeType": "FunctionCall",
        "expression": expression,
        "arguments": args or [],
        "src": src,
    }


def _statement(expression: dict) -> dict:
    return {"nodeType": "ExpressionStatement", "expression": expression, "src": expression["src"]}


def _eq(left: dict, right: dict, src: str) -> dict:
    return {
        "nodeType": "BinaryOperation",
        "operator": "==",
        "leftExpression": left,
        "rightExpression": right,
        "src": src,
    }


def _standard_output() -> dict:
    tx_origin_gate = _eq(
        _member(_identifier("tx"), "origin"),
        _member(_identifier("msg"), "sender"),
        "120:28:0",
    )
    owner_gate = _eq(
        _member(_identifier("msg"), "sender"),
        _identifier("owner"),
        "150:20:0",
    )
    code_size_gate = {
        "nodeType": "BinaryOperation",
        "operator": ">",
        "leftExpression": _member(_member(_identifier("target"), "code"), "length"),
        "rightExpression": {"nodeType": "Literal", "value": "0", "src": "180:1:0"},
        "src": "170:24:0",
    }
    owner_write = {
        "nodeType": "Assignment",
        "operator": "=",
        "leftHandSide": _identifier("owner", "200:5:0"),
        "rightHandSide": _member(_identifier("msg"), "sender"),
        "src": "200:18:0",
    }

    return {
        "sources": {
            "Wallet.sol": {
                "id": 0,
                "ast": {
                    "nodes": [
                        {
                            "nodeType": "ContractDefinition",
                            "name": "Wallet",
                            "contractKind": "contract",
                            "src": "0:420:0",
                            "baseContracts": [],
                            "nodes": [
                                {
                                    "nodeType": "VariableDeclaration",
                                    "name": "owner",
                                    "stateVariable": True,
                                    "src": "20:13:0",
                                },
                                {
                                    "nodeType": "FunctionDefinition",
                                    "name": "execute",
                                    "kind": "function",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "src": "80:320:0",
                                    "modifiers": [
                                        {"modifierName": {"name": "onlyOwner"}}
                                    ],
                                    "parameters": {
                                        "parameters": [
                                            {
                                                "nodeType": "VariableDeclaration",
                                                "name": "target",
                                                "typeName": {"name": "address"},
                                                "storageLocation": "default",
                                                "src": "90:14:0",
                                            },
                                            {
                                                "nodeType": "VariableDeclaration",
                                                "name": "data",
                                                "typeName": {"name": "bytes"},
                                                "storageLocation": "calldata",
                                                "src": "106:19:0",
                                            },
                                        ]
                                    },
                                    "body": {
                                        "nodeType": "Block",
                                        "src": "126:260:0",
                                        "statements": [
                                            _statement(_call(_identifier("require"), [tx_origin_gate], "120:38:0")),
                                            _statement(_call(_identifier("require"), [owner_gate], "150:30:0")),
                                            _statement(_call(_identifier("require"), [code_size_gate], "170:34:0")),
                                            _statement(owner_write),
                                            _statement(_call(_member(_identifier("target"), "call"), [_identifier("data")], "225:18:0")),
                                            _statement(_call(_member(_identifier("target"), "delegatecall"), [_identifier("data")], "250:26:0")),
                                            _statement(_call(_member(_identifier("receiver"), "transfer"), [], "280:20:0")),
                                            _statement(_call(_identifier("ecrecover"), [], "310:18:0")),
                                            _statement(_call(_identifier("_afterExecute"), [], "340:16:0")),
                                        ],
                                    },
                                },
                            ],
                        }
                    ]
                },
            }
        }
    }


def _fact_names(function_ir, bucket: str) -> set[str]:
    return {fact.name for fact in getattr(function_ir, bucket)}


def test_semantic_ir_extracts_function_level_ast_facts():
    project = semantic_ir_from_standard_output(SOURCES, _standard_output())

    assert project.compiler_status == "ok"
    assert project.analysis_depth == "standard_json_ast_ir"
    assert project.summary()["functions"] == 1
    assert project.summary()["facts_by_kind"]["delegatecalls"] == 1
    assert project.summary()["facts_by_kind"]["tx_origin_checks"] == 1

    function = project.functions[0]
    assert function.qualified_name == "Wallet.execute"
    assert function.modifiers == ["onlyOwner"]
    assert function.source.file == "Wallet.sol"
    assert _fact_names(function, "storage_reads") == {"owner"}
    assert _fact_names(function, "storage_writes") == {"owner"}
    assert _fact_names(function, "external_calls") == {"target.call"}
    assert _fact_names(function, "delegatecalls") == {"target.delegatecall"}
    assert _fact_names(function, "value_transfers") == {"receiver.transfer"}
    assert _fact_names(function, "signature_checks") == {"ecrecover"}
    assert _fact_names(function, "internal_calls") == {"_afterExecute"}
    assert _fact_names(function, "calldata_parameters") == {"data"}
    assert "tx.origin==msg.sender" in _fact_names(function, "tx_origin_checks")
    assert "target.code.length > 0" in _fact_names(function, "code_size_checks")

    payload = project.to_dict()
    assert payload["functions"][0]["qualified_name"] == "Wallet.execute"
    assert payload["functions"][0]["calldata_parameters"][0]["detail"]["type"] == "bytes"


def test_semantic_ir_extracts_modifier_body_facts():
    output = {
        "sources": {
            "Gate.sol": {
                "id": 0,
                "ast": {
                    "nodes": [
                        {
                            "nodeType": "ContractDefinition",
                            "name": "Gate",
                            "contractKind": "contract",
                            "src": "0:240:0",
                            "baseContracts": [],
                            "nodes": [
                                {
                                    "nodeType": "ModifierDefinition",
                                    "name": "onlyPlainEOA",
                                    "src": "40:90:0",
                                    "parameters": {
                                        "parameters": [
                                            {
                                                "nodeType": "VariableDeclaration",
                                                "name": "account",
                                                "typeName": {"name": "address"},
                                                "storageLocation": "default",
                                                "src": "58:15:0",
                                            }
                                        ]
                                    },
                                    "body": {
                                        "nodeType": "Block",
                                        "src": "76:50:0",
                                        "statements": [
                                            _statement(
                                                _call(
                                                    _identifier("require"),
                                                    [
                                                        {
                                                            "nodeType": "BinaryOperation",
                                                            "operator": "==",
                                                            "leftExpression": _member(
                                                                _member(_identifier("account"), "code"),
                                                                "length",
                                                            ),
                                                            "rightExpression": {
                                                                "nodeType": "Literal",
                                                                "value": "0",
                                                                "src": "104:1:0",
                                                            },
                                                            "src": "82:24:0",
                                                        }
                                                    ],
                                                    "78:30:0",
                                                )
                                            )
                                        ],
                                    },
                                },
                                {
                                    "nodeType": "FunctionDefinition",
                                    "name": "claim",
                                    "kind": "function",
                                    "visibility": "external",
                                    "stateMutability": "nonpayable",
                                    "src": "140:50:0",
                                    "modifiers": [
                                        {"modifierName": {"name": "onlyPlainEOA"}}
                                    ],
                                    "parameters": {"parameters": []},
                                    "body": {"nodeType": "Block", "statements": [], "src": "180:2:0"},
                                },
                            ],
                        }
                    ]
                },
            }
        }
    }

    project = semantic_ir_from_standard_output({"Gate.sol": "contract Gate {}"}, output)

    modifier = next(function for function in project.functions if function.kind == "modifier")
    assert modifier.qualified_name == "Gate.onlyPlainEOA"
    assert _fact_names(modifier, "code_size_checks") == {"account.code.length == 0"}
    assert project.summary()["facts_by_kind"]["code_size_checks"] == 1


def test_semantic_ir_marks_missing_solc_as_unavailable():
    project = build_semantic_ir(SOURCES, solc="definitely-not-solc")

    assert project.compiler_status == "unavailable"
    assert project.analysis_depth == "semantic_ir_unavailable"
    assert project.functions == []
    assert project.fallback_reason
