// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignTimer {
    uint public lastRun;
    function run() external { lastRun = block.timestamp; }
}