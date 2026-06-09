// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: cross-chain delegation replay
/// @notice AA7702-004 — replay_boundary bypass
contract CrossChainDelegation {
    mapping(bytes32 => bool) public executed;

    struct DelegationAuth {
        address delegator;
        address target;
        uint256 nonce;
        // Missing: chainId binding
        bytes signature;
    }

    function executeDelegation(DelegationAuth calldata auth) external {
        bytes32 hash = keccak256(abi.encode(
            auth.delegator, auth.target, auth.nonce
            // No chain_id in hash — replayable across chains
        ));

        require(!executed[hash], "Already executed");
        require(_verify(hash, auth.signature, auth.delegator), "Bad sig");

        executed[hash] = true;
        (bool ok,) = auth.target.delegatecall(
            abi.encodeWithSignature("execute()")
        );
        require(ok, "Delegation failed");
    }

    function _verify(bytes32, bytes memory, address) internal pure returns (bool) {
        return true; // Simplified for benchmark
    }
}
