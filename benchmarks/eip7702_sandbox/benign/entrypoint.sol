// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignAccess {
    mapping(address => bool) public hasAccess;
    function grant(address a) external { hasAccess[a] = true; }
}