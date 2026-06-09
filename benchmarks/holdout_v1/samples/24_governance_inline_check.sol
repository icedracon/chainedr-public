// SPDX-License-Identifier: MIT
// Inline governance auth check pattern: require(msg.sender ==
// governance). Inline-auth suppression must keep AA7702-001 quiet.
pragma solidity ^0.8.20;

contract GovernanceVault {
    address public governance;

    constructor() { governance = msg.sender; }

    function emergencyAction() external {
        require(msg.sender == governance, "not gov");
        // Defence-in-depth comparison — gated function, should not fire.
        if (tx.origin == msg.sender) {
            // ... do thing
        }
    }
}
