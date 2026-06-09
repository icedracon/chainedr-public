// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MissingRevocation {
    mapping(address => address) public delegates;
    function setDelegate(address target) external {
        delegates[msg.sender] = target;
    }
}