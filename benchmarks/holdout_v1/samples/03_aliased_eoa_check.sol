// SPDX-License-Identifier: MIT
// Aliased pattern lifted from a real audit finding: the literal
// tx.origin == msg.sender check is hidden behind two local-variable
// assignments. Same bug, harder to grep.
pragma solidity ^0.8.20;

contract AliasedEOACheck {
    function distribute() external {
        address initiator = tx.origin;
        address caller    = msg.sender;
        // ...some computation...
        require(initiator == caller, "not eoa");
        // ...payout logic
    }
}
