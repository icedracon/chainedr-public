// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: batch authorization replay without nonce
/// @notice AA7702-011 — replay_boundary bypass
contract BatchAuthReplay {
    mapping(bytes32 => bool) public executed;

    struct AuthOp {
        address target;
        bytes data;
        bytes signature;
    }

    function executeBatch(AuthOp[] calldata ops) external {
        for (uint i = 0; i < ops.length; i++) {
            // No per-operation nonce — batch can be replayed
            bytes32 opHash = keccak256(abi.encode(ops[i].target, ops[i].data));
            require(!executed[opHash], "Already executed");
            executed[opHash] = true;
            (bool ok,) = ops[i].target.call(ops[i].data);
            require(ok, "Call failed");
        }
    }
}
