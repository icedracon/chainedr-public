// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BenignOracle {
    uint public price;
    function setPrice(uint p) external { price = p; }
}