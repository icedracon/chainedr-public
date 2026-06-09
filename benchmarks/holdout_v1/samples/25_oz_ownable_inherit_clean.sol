// SPDX-License-Identifier: MIT
// Contract that inherits from a known access-control base (Ownable)
// and uses its modifiers throughout. Plain administrative entry; no
// 7702-relevant patterns. Nothing should fire.
pragma solidity ^0.8.20;

abstract contract Ownable {
    address private _owner;
    constructor() { _owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == _owner, "not owner"); _; }
}

contract InheritsOwnable is Ownable {
    uint256 public value;

    function setValue(uint256 v) external onlyOwner {
        value = v;
    }
}
