// SPDX-License-Identifier: MIT
// Cross-function state-variable flow: tx.origin is stored on
// startSession() and later compared against msg.sender in act(). The
// guard logic is split across two unguarded entry points and is
// semantically broken under EIP-7702.
pragma solidity ^0.8.20;

contract StateFlowEOA {
    address public initiator;

    function startSession() external {
        initiator = tx.origin;
    }

    function act() external {
        require(initiator == msg.sender, "session mismatch");
        // ...
    }
}
