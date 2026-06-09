import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from bytecode_oracle import profile_bytecode  # noqa: E402
from detector_plugin import Finding, Severity  # noqa: E402
from eip7702_detector import EIP7702Finding  # noqa: E402
from proof_adapters import (  # noqa: E402
    attach_proof_adapters,
    build_bytecode_proof_adapters,
    build_proof_adapters,
)


def test_signature_and_erc1271_adapters_attach_to_finding_metadata():
    finding = Finding(
        detector="eip7702",
        rule_id="AA7702-016",
        severity=Severity.MEDIUM,
        title="raw signature path",
        description="ecrecover without smart-account fallback",
        metadata={
            "semantic_context": {
                "signature_model": {
                    "verifies_signature": True,
                    "binds_chain_id": False,
                    "binds_contract": False,
                    "binds_nonce": False,
                    "uses_erc1271": False,
                    "uses_erc6492": False,
                    "missing": ["chain_id", "verifying_contract", "nonce", "erc1271_fallback"],
                }
            },
            "proof_recipe": {
                "check_id": "AA7702-016",
                "proof_status": "STATIC_CANDIDATE",
                "kind": "signature_context_review",
            },
        },
    )

    attach_proof_adapters([finding])

    adapters = finding.metadata["proof_adapters"]
    assert [a["adapter_id"] for a in adapters] == [
        "signature_domain_replay",
        "erc1271_6492_signature_probe",
    ]
    assert "replay_same_signature_with_different_chain_id" in adapters[0]["mutations"]
    assert finding.metadata["proof_recipe"]["adapters"] == adapters


def test_behavior_flip_adapter_marks_aa7702_002_confirmable():
    finding = {
        "check": "AA7702-002",
        "proof_recipe": {
            "kind": "fork_oracle_behavior_flip",
            "proof_status": "CONFIRMABLE",
        },
    }

    adapters = build_proof_adapters(finding)

    assert adapters[0]["adapter_id"] == "eip7702_behavior_flip_probe"
    assert adapters[0]["status"] == "SUPPORTED_BY_SCAN_CONFIRM"
    assert adapters[0]["proof_status"] == "CONFIRMABLE"


def test_legacy_eip7702_finding_uses_check_id_for_adapters():
    finding = EIP7702Finding(
        check_id="AA7702-002",
        title="isContract gate",
        severity="HIGH",
        description="code.length gate assumes EOA",
        location="L1",
        cwe="CWE-693",
        recommendation="Use explicit authorization",
        confidence=0.8,
    )

    attach_proof_adapters([finding])

    assert finding.metadata["proof_adapters"][0]["adapter_id"] == "eip7702_behavior_flip_probe"
    assert finding.metadata["proof_recipe"]["adapters"] == finding.metadata["proof_adapters"]


def test_userop_adapter_names_validation_mutations():
    finding = {
        "check": "AA7562-007",
        "proof_recipe": {"kind": "userop_validation_review"},
        "semantic_context": {
            "userop_model": {
                "missing": ["userOpHash", "nonce", "entryPoint", "signature_verification"],
            }
        },
    }

    adapters = build_proof_adapters(finding)

    assert len(adapters) == 1
    assert adapters[0]["adapter_id"] == "erc4337_userop_validation"
    assert "swap_userOpHash_or_callData_without_resigning" in adapters[0]["mutations"]
    assert "submit_userOp_with_empty_or_random_signature" in adapters[0]["mutations"]


def test_bytecode_profile_gets_asset_and_guard_adapter_plans():
    bytecode = (
        "0x"
        "6370a0823114"  # balanceOf(address)
        "63a9059cbb14"  # transfer(address,uint256)
        "631626ba7e14"  # isValidSignature(bytes32,bytes)
        "633644e51514"  # DOMAIN_SEPARATOR()
        "3373b1280932da6df283be6dddd99f2a147d41773988f1"
    )
    profile = profile_bytecode(bytecode, "0x0000000000000000000000000000000000000001")

    adapters = build_bytecode_proof_adapters(profile)

    ids = {a["adapter_id"] for a in adapters}
    assert "bytecode_asset_sweep_probe" in ids
    assert "bytecode_guard_surface_review" in ids
    sweep = next(a for a in adapters if a["adapter_id"] == "bytecode_asset_sweep_probe")
    assert "erc20_balance_or_allowance_diff" in sweep["recommended_probes"]
    assert "token_movement_surface" in sweep["proof_surfaces"]
