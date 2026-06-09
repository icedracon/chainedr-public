// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: ecrecover-only auth without EIP-1271
/// @notice AA7702-016 — validation_boundary bypass
contract EcrecoverOnlyAuth {
    mapping(bytes32 => bool) public executed;

    function executeWithSig(
        address to, bytes calldata data, bytes32 hash,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(!executed[hash], "Replayed");
        // ecrecover only — no isValidSignature for contract wallets
        address signer = ecrecover(hash, v, r, s);
        require(signer == msg.sender, "Bad signature");
        executed[hash] = true;
        (bool ok,) = to.call(data);
        require(ok);
    }
}
