// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignToken {
    mapping(address => uint) public balance;
    function mint() external { balance[msg.sender] += 1; }
}