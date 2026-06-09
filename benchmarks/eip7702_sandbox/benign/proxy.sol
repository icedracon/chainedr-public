// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignVault {
    uint public total;
    function deposit() external payable { total += msg.value; }
}