// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: chain_id validated in delegation authorization
/// @notice AA7702-004 — prevents cross-chain replay
contract SecureDelegationAuth {
    mapping(bytes32 => bool) public usedAuthorizations;

    function processAuthorization(
        address authority, uint256 chainId, uint256 nonce, bytes calldata sig
    ) external {
        require(chainId == block.chainid, "Wrong chain");
        require(chainId != 0, "Wildcard chain_id rejected");
        bytes32 authHash = keccak256(abi.encode(authority, chainId, nonce));
        require(!usedAuthorizations[authHash], "Already used");
        usedAuthorizations[authHash] = true;
    }
}
