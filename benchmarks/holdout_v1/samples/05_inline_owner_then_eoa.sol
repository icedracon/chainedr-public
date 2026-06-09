// SPDX-License-Identifier: MIT
// Inline access check followed by a defence-in-depth tx.origin
// comparison. The function is effectively gated; AA7702-001 should not
// fire. This is the regression sample that protects the
// inline-auth-aware suppression from drifting back.
pragma solidity ^0.8.20;

contract InlineOwnerGuard {
    address private owner;

    constructor() { owner = msg.sender; }

    function privileged() external {
        require(msg.sender == owner, "not owner");
        require(tx.origin == msg.sender, "not eoa");
        // ... privileged action
    }
}
