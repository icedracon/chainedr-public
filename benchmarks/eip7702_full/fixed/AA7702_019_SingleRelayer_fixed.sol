// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: relayer allowlist instead of single hardcoded relayer
/// @notice AA7702-019 — no single point of failure
contract MultiRelayerWallet {
    mapping(address => bool) public allowedRelayers;
    address public owner;

    constructor() { owner = msg.sender; }

    function setRelayer(address relayer, bool allowed) external {
        require(msg.sender == owner, "Not owner");
        allowedRelayers[relayer] = allowed;
    }

    function relayExecute(address to, bytes calldata data) external {
        require(allowedRelayers[msg.sender], "Not allowed relayer");
        (bool ok,) = to.call(data);
        require(ok);
    }

    function ownerExecute(address to, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = to.call(data);
        require(ok);
    }
}
