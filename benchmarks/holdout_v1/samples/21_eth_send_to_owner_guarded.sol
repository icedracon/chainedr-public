// SPDX-License-Identifier: MIT
// ETH send to owner from inside an onlyOwner function. With the
// access-gated AA7702-003 suppression this should NOT fire — owner
// reentering themselves is a self-harm scenario.
pragma solidity ^0.8.20;

contract GuardedTreasury {
    address payable private _owner;
    constructor() { _owner = payable(msg.sender); }

    modifier onlyOwner() { require(msg.sender == _owner, "not owner"); _; }

    function withdraw(uint256 amount) external onlyOwner {
        _owner.transfer(amount);
    }
}
