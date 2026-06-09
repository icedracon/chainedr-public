// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
contract IsContractFixed {
    mapping(address => bool) public allowlist;
    function addToAllowlist(address a) external { allowlist[a] = true; }
    function onlyAllowlisted() external { require(allowlist[msg.sender]); }
}