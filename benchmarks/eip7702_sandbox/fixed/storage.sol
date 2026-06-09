// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract RevocationFixed {
    mapping(address => address) public delegates;
    function updateDelegation(address target) external {
        delegates[msg.sender] = target;
    }
    function revokeDelegation() external {
        delete delegates[msg.sender];
    }
}