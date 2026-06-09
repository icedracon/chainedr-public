import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from reviewer_confidence import reviewer_confidence_for_finding  # noqa: E402


def test_regex_static_candidate_is_not_overstated():
    finding = {
        "analysis_depth": "regex",
        "proof_status": "STATIC_CANDIDATE",
        "proof_recipe": {"proof_status": "STATIC_CANDIDATE"},
    }

    confidence = reviewer_confidence_for_finding(finding)

    assert confidence["grade"] in {"C", "D"}
    assert confidence["tier"] == "INFORMATIONAL"
    assert "static signal" in confidence["tier_reason"]
    assert "semantic_or_ast_confirmation" in confidence["gaps"]
    assert "dynamic_confirmation_or_manual_reproduction" in confidence["gaps"]


def test_semantic_confirmable_finding_is_review_ready():
    finding = {
        "analysis_depth": "deep_ast",
        "proof_status": "CONFIRMABLE",
        "auto_poc_status": "supported_by_confirm_demo",
        "metadata": {
            "semantic_context": {
                "analysis": "deep_ast",
                "semantic_index": {
                    "summary": {
                        "proxy_contracts": ["WalletProxy"],
                        "delegation_contracts": [],
                    }
                },
                "signature_model": {"missing": ["nonce"]},
            },
            "proof_recipe": {
                "proof_status": "CONFIRMABLE",
                "adapters": [{"adapter_id": "eip7702_behavior_flip_probe"}],
                "auto_poc_status": "supported_by_confirm_demo",
            },
        },
    }

    confidence = reviewer_confidence_for_finding(finding)

    assert confidence["grade"] in {"A", "B"}
    assert confidence["tier"] == "CANDIDATE"
    assert "deep_ast" in confidence["evidence"]
    assert "project_semantic_index" in confidence["evidence"]
    assert "proxy_or_delegation_context" in confidence["evidence"]
    assert "proof_adapter_available" in confidence["evidence"]
    assert "complete_signature_or_userop_model" in confidence["gaps"]


def test_standard_json_ast_finding_gets_semantic_evidence():
    finding = {
        "analysis_depth": "standard_json_ast",
        "proof_recipe": {"proof_status": "STATIC_CANDIDATE"},
    }

    confidence = reviewer_confidence_for_finding(finding)

    assert "standard_json_ast" in confidence["evidence"]
    assert confidence["grade"] in {"B", "C"}
    assert confidence["tier"] == "CANDIDATE"


def test_semantic_ir_facts_get_reviewer_evidence():
    finding = {
        "analysis_depth": "standard_json_ast",
        "semantic_context": {
            "analysis": "standard_json_ast",
            "semantic_ir": {
                "analysis_depth": "standard_json_ast_ir",
                "summary": {
                    "facts": 2,
                    "facts_by_kind": {"code_size_checks": 1, "external_calls": 1},
                },
                "functions": [],
            },
            "call_graph": {
                "summary": {"edges": 1, "unresolved_edges": 0},
                "edges": [
                    {
                        "source": "Airdrop.claim",
                        "target": "Airdrop.onlyPlainEOA",
                        "kind": "modifier",
                    }
                ],
            },
        },
        "proof_recipe": {"proof_status": "STATIC_CANDIDATE"},
    }

    confidence = reviewer_confidence_for_finding(finding)

    assert "semantic_ir_flow_facts" in confidence["evidence"]
    assert "ir_call_graph" in confidence["evidence"]
    assert confidence["analysis_depth"] == "standard_json_ast"


def test_dynamic_confirmed_finding_gets_strong_evidence_grade():
    finding = {
        "analysis_depth": "dynamic_confirmation",
        "metadata": {
            "dynamic_confirmation": {"status": "confirmed"},
            "proof_recipe": {"proof_status": "CONFIRMED_IMPACT"},
        },
    }

    confidence = reviewer_confidence_for_finding(finding)

    assert confidence["grade"] == "A"
    assert confidence["label"] == "strong_evidence"
    assert confidence["tier"] == "CONFIRMED"
    assert "confirmed_impact" in confidence["evidence"]
