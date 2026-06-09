// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: storage slot collision in delegation target
/// @notice AA7702-007 — storage_boundary bypass
contract DelegationStorageClash {
    address public owner;
    uint256 public nonce;
    address public guardian;
    bool public paused;

    constructor() { owner = msg.sender; }

    function executeAs(address to, bytes calldata data) external {
        require(msg.sender == owner || msg.sender == guardian, "Unauthorized");
        require(!paused, "Paused");
        nonce++;
        (bool ok,) = to.call(data);
        require(ok, "Call failed");
    }
}
