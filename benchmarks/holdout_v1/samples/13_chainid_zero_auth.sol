// SPDX-License-Identifier: MIT
// EIP-7702 authorization-style action with chain_id=0 in the digest.
// chain_id=0 is the all-chains wildcard; replay across chains is
// possible. AA7702-004 should fire.
pragma solidity ^0.8.20;

contract NaiveDelegationAuth {
    function authorize(address target, uint8 v, bytes32 r, bytes32 s) external {
        // chain_id is hard-coded to 0 — replayable across all chains.
        bytes32 digest = keccak256(abi.encode(uint256(0), target, address(this)));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        // ... apply authorization
    }
}
