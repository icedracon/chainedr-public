// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: single hardcoded relayer with no fallback
/// @notice AA7702-019 — revocation_boundary bypass
contract SingleRelayerWallet {
    address public constant RELAYER = 0x1234567890AbcdEF1234567890aBcdef12345678;
    address public owner;

    constructor() { owner = msg.sender; }

    function relayExecute(address to, bytes calldata data) external {
        require(msg.sender == RELAYER, "Only relayer");
        (bool ok,) = to.call(data);
        require(ok);
    }

    // No alternative execution path if RELAYER goes down
}
