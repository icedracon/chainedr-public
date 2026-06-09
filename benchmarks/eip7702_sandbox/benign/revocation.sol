// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignRegistry {
    mapping(address => address) public registry;
    function register(address v) external { registry[msg.sender] = v; }
}