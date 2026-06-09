// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignNFT {
    uint public nextId;
    mapping(uint => address) public owners;
    function mint() external { owners[nextId++] = msg.sender; }
}