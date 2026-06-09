// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
contract BenignStorage {
    uint public value;
    function set(uint v) external { value = v; }
}