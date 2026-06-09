import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import beta_semantics  # noqa: E402
from eip7702_detector import (  # noqa: E402
    _strip_comments,
    detect_callback_reentrancy,
    detect_cross_chain_replay,
    detect_delegatecall_from_delegation,
    detect_tx_origin_eoa_bypass,
)


def test_real_tx_origin_detector_output_is_normalized():
    beta_semantics.install()
    source = """
pragma solidity ^0.8.20;
contract Gate {
    function enter() external {
        require(tx.origin == msg.sender, "EOA only");
    }
}
"""
    finding = detect_tx_origin_eoa_bypass(_strip_comments(source))[0]
    assert "changes tx.origin==msg.sender security assumptions" in finding.title
    assert "must not be treated as proof of non-programmable behavior" in finding.description
    assert "Do not rely on `tx.origin == msg.sender` as a security boundary" in finding.recommendation


def test_real_callback_detector_output_preserves_stipend_caveat():
    beta_semantics.install()
    source = """
pragma solidity ^0.8.20;
contract Vault {
    function withdrawToEOA(address payable user, uint256 amount) external {
        user.transfer(amount);
    }
}
"""
    finding = detect_callback_reentrancy(_strip_comments(source))[0]
    assert "normal gas stipend still applies" in finding.description
    assert "delegation code runs in a separate context" not in finding.description


def test_real_chain_id_zero_detector_output_is_policy_review():
    beta_semantics.install()
    source = """
pragma solidity ^0.8.20;
contract EIP7702AuthorizationRegistry {
    function authorize() external pure returns (uint256) {
        uint256 chainId = 0;
        return chainId;
    }
}
"""
    finding = detect_cross_chain_replay(_strip_comments(source))[0]
    assert finding.check_id == "AA7702-004"
    assert finding.severity == "MEDIUM"
    assert finding.confidence == 0.72
    assert "universal authorization policy review" in finding.title
    assert "intentionally permits `chain_id=0`" in finding.description


def test_real_nested_delegatecall_output_does_not_recommend_tx_origin():
    beta_semantics.install()
    source = """
pragma solidity ^0.8.20;
contract EIP7702DelegationTarget {
    function executeAs(address implementation, bytes calldata data) external {
        (bool ok,) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
"""
    finding = detect_delegatecall_from_delegation(_strip_comments(source))[0]
    assert finding.check_id == "AA7702-006"
    assert "preserves the current call-frame sender" in finding.description
    assert "do not use `tx.origin`" in finding.recommendation
