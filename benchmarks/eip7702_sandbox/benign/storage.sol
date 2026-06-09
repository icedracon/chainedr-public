// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignLogger {
    event Log(string msg);
    function log(string calldata m) external { emit Log(m); }
}