// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DelegationStorageCollision {
    address public owner;
    uint public value;
    uint public count;
    constructor() { owner = msg.sender; }
    function setValue(uint v) external { require(msg.sender == owner); value = v; }
}