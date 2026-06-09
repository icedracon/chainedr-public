// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignCounter {
    uint public count;
    function increment() external { count++; }
}