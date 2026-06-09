// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: sequential nonce validation for batch auth
/// @notice AA7702-011 — prevents replay and enforces ordering
contract SecureBatchAuth {
    mapping(address => uint256) public authNonces;

    struct AuthEntry {
        address authority;
        uint256 nonce;
        address target;
        bytes data;
    }

    function processBatch(AuthEntry[] calldata entries) external {
        for (uint i = 0; i < entries.length; i++) {
            AuthEntry calldata e = entries[i];
            require(e.nonce == authNonces[e.authority], "Invalid nonce");
            require(i == 0 || e.nonce > entries[i-1].nonce, "Must be sequential order");
            authNonces[e.authority]++;
            (bool ok,) = e.target.call(e.data);
            require(ok, "Exec failed");
        }
    }
}
