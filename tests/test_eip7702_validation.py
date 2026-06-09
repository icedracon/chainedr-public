"""Tests for ERC-7562/EIP-7702 validation-sandbox checks."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector_plugin import ScanOptions
from eip7702_validation import EIP7702ValidationDetector, build_validation_model
from proof_adapters import attach_proof_adapters
from project_context import discover_project


VALIDATION_ENVIRONMENT_VULN = """
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
}

contract Account {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        returns (uint256 validationData)
    {
        require(tx.origin == userOp.sender, "delegated EOA only");
        require(block.timestamp < 2000000000, "expired");
        return 0;
    }
}
"""


VALUE_CALL_VULN = """
pragma solidity ^0.8.23;

struct PackedUserOperation { address sender; uint256 nonce; }

contract Paymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 hash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData)
    {
        payable(userOp.sender).call{value: 1 wei}("");
        return ("", 0);
    }
}
"""


CODE_DRIFT_VULN = """
pragma solidity ^0.8.23;

struct PackedUserOperation { address sender; uint256 nonce; }

contract Account {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 hash, uint256 missingFunds)
        external
        returns (uint256 validationData)
    {
        require(userOp.sender.code.length > 0, "missing code");
        return 0;
    }
}
"""


AUTH_TUPLE_VULN = """
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address[] authorizationList;
}

contract BundlerSandbox {
    function simulateValidation(UserOperation calldata userOp) external {
        require(userOp.authorizationList.length > 0, "missing auth");
    }
}
"""


DELEGATE_ROLE_VULN = """
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    address paymaster;
    bytes authorization;
}

contract Paymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 hash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData)
    {
        require(userOp.authorization.length > 0, "EIP-7702 delegated paymaster required");
        require(userOp.paymaster != address(0), "missing paymaster");
        return ("", 0);
    }
}
"""


DELEGATE_CONSISTENCY_VULN = """
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address delegate;
    bytes authorization;
}

contract BundlerSandbox {
    function handleOps(UserOperation[] calldata ops) external {
        for (uint256 i = 0; i < ops.length; i++) {
            require(ops[i].authorization.length > 0, "missing 7702 authorization");
        }
    }
}
"""


HASH_BINDING_VULN = """
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    bytes signature;
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0x1234);
    }
}

contract Account {
    address public entryPoint;
    address public owner;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        bytes32 partial = keccak256(abi.encode(userOp.sender));
        address signer = ECDSA.recover(partial, userOp.signature);
        require(signer == owner, "bad signature");
        return 0;
    }
}
"""


ENTRYPOINT_GATE_VULN = """
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    bytes signature;
}

contract Account {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        returns (uint256 validationData)
    {
        require(userOpHash != bytes32(0), "missing context");
        return userOp.signature.length == 65 ? 0 : 1;
    }
}
"""


PREVERIFICATION_GAS_VULN = """
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    uint256 preVerificationGas;
    address[] authorizationList;
}

contract BundlerSandbox {
    function simulateValidation(UserOperation calldata userOp) external {
        require(userOp.authorizationList.length == 1, "one EIP-7702 auth");
        uint256 gasBudget = userOp.preVerificationGas;
        require(gasBudget > 21000, "gas too low");
    }
}
"""


SAFE_VALIDATION = """
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address delegate;
    address[] authorizationList;
}

contract SafeBundlerSandbox {
    mapping(address => address) public senderToDelegate;
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        view
        onlyEntryPoint
        returns (uint256 validationData)
    {
        bytes32 expectedCodeHash = bytes32(uint256(1));
        bytes32 observed = userOp.sender.codehash;
        require(observed == expectedCodeHash, "code drift");
        return 0;
    }

    function simulateValidation(UserOperation calldata userOp) external pure {
        require(userOp.authorizationList.length == 1, "one EIP-7702 auth");
    }

    function handleOps(UserOperation[] calldata ops) external {
        for (uint256 i = 0; i < ops.length; i++) {
            address known = senderToDelegate[ops[i].sender];
            require(known == address(0) || known == ops[i].delegate, "delegateMismatch");
        }
    }
}
"""


VALIDATION_MODULE_INTERFACE = """
pragma solidity ^0.8.23;

interface IValidationModule {}
struct PackedUserOperation { address sender; bytes signature; }

contract SingleSignerValidationModule is IValidationModule {
    mapping(uint32 entityId => mapping(address account => address)) public signers;

    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        returns (uint256)
    {
        if (signers[entityId][userOp.sender] == address(0) || userOpHash == bytes32(0)) {
            return 1;
        }
        return 0;
    }

    function validateSignature(address account, uint32 entityId, address, bytes32 digest, bytes calldata)
        external
        view
        returns (bytes4)
    {
        if (signers[entityId][account] != address(0) && digest != bytes32(0)) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }
}
"""


def _scan_source(tmp_path, source):
    (tmp_path / "Account.sol").write_text(source)
    ctx = discover_project(tmp_path)
    result = EIP7702ValidationDetector()._timed_scan(
        ctx,
        ScanOptions(use_slither=False, use_ast=False),
    )
    return result


def test_blocked_environment_opcode_in_validation(tmp_path):
    result = _scan_source(tmp_path, VALIDATION_ENVIRONMENT_VULN)
    finding = next(f for f in result.findings if f.rule_id == "AA7562-001")
    assert finding.metadata["erc7562_rule"] == "OP-011/OP-012"
    assert finding.metadata["pre_behavior_trace"]["violated_boundary"] == "validation_boundary"


def test_value_call_in_validation(tmp_path):
    result = _scan_source(tmp_path, VALUE_CALL_VULN)
    assert any(f.rule_id == "AA7562-002" for f in result.findings)


def test_code_drift_without_pinned_hash(tmp_path):
    result = _scan_source(tmp_path, CODE_DRIFT_VULN)
    assert any(f.rule_id == "AA7562-003" for f in result.findings)


def test_multiple_authorization_tuple_acceptance(tmp_path):
    result = _scan_source(tmp_path, AUTH_TUPLE_VULN)
    assert any(f.rule_id == "AA7562-004" for f in result.findings)


def test_delegated_non_sender_entity(tmp_path):
    result = _scan_source(tmp_path, DELEGATE_ROLE_VULN)
    assert any(f.rule_id == "AA7562-005" for f in result.findings)


def test_batch_delegate_consistency(tmp_path):
    result = _scan_source(tmp_path, DELEGATE_CONSISTENCY_VULN)
    assert any(f.rule_id == "AA7562-006" for f in result.findings)


def test_signature_validation_must_bind_userop_hash(tmp_path):
    result = _scan_source(tmp_path, HASH_BINDING_VULN)
    finding = next(f for f in result.findings if f.rule_id == "AA7562-007")
    assert finding.metadata["sandbox_boundary"] == "validation_boundary"
    assert finding.metadata["pre_behavior_trace"]["bypass_class"] == "signature_domain_binding_bypass"
    assert finding.metadata["validation_model"]["has_validate_userop"] is True
    assert "userOpHash" in finding.metadata["semantic_context"]["userop_model"]["missing"]
    assert finding.metadata["proof_recipe"]["kind"] == "userop_validation_review"


def test_validation_requires_entrypoint_gate(tmp_path):
    result = _scan_source(tmp_path, ENTRYPOINT_GATE_VULN)
    finding = next(f for f in result.findings if f.rule_id == "AA7562-008")
    assert "validateUserOp" in finding.metadata["validation_model"]["ungated_validation_functions"]
    assert "entryPoint" in finding.metadata["semantic_context"]["userop_model"]["missing"]


def test_validation_module_interface_is_not_entrypoint_account(tmp_path):
    result = _scan_source(tmp_path, VALIDATION_MODULE_INTERFACE)
    assert not any(f.rule_id == "AA7562-008" for f in result.findings)


def test_preverification_gas_includes_7702_authorization_cost(tmp_path):
    result = _scan_source(tmp_path, PREVERIFICATION_GAS_VULN)
    assert any(f.rule_id == "AA7562-009" for f in result.findings)


def test_validation_model_records_function_level_userop_facts():
    model = build_validation_model(ENTRYPOINT_GATE_VULN)
    validate = model["validation_functions"][0]

    assert validate["name"] == "validateUserOp"
    assert validate["entrypoint_gated"] is False
    assert validate["uses_userop_hash"] is True
    assert model["missing_userop_bindings"] == [
        "nonce",
        "entryPoint",
        "signature_verification",
    ]


def test_validation_model_records_bundler_7702_gas_accounting():
    model = build_validation_model(PREVERIFICATION_GAS_VULN)
    bundler = model["bundler_functions"][0]

    assert bundler["handles_eip7702_authorization"] is True
    assert bundler["checks_single_authorization"] is True
    assert bundler["uses_preverification_gas"] is True
    assert bundler["includes_7702_gas_cost"] is False


def test_validation_metadata_drives_userop_proof_adapter(tmp_path):
    result = _scan_source(tmp_path, HASH_BINDING_VULN)
    finding = next(f for f in result.findings if f.rule_id == "AA7562-007")

    attach_proof_adapters([finding])

    adapter = finding.metadata["proof_adapters"][0]
    assert adapter["adapter_id"] == "erc4337_userop_validation"
    assert "swap_userOpHash_or_callData_without_resigning" in adapter["mutations"]
    assert "reuse_or_skip_userOp_nonce" in adapter["mutations"]


def test_safe_validation_contract_is_clean(tmp_path):
    result = _scan_source(tmp_path, SAFE_VALIDATION)
    assert result.findings == []


def test_benchmark_labels_cover_validation_rules():
    labels_path = Path(__file__).resolve().parents[1] / "benchmarks" / "eip7702_sandbox" / "labels.json"
    labels = json.loads(labels_path.read_text())
    expected = {label["expected_rule"] for label in labels["samples"] if label["expected_rule"]}
    assert {
        "AA7562-001",
        "AA7562-002",
        "AA7562-003",
        "AA7562-004",
        "AA7562-005",
        "AA7562-006",
        "AA7562-007",
        "AA7562-008",
        "AA7562-009",
    } <= expected
