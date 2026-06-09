// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DelegationInitRace {
    address public admin;
    bool public initialized;
    function initialize(address _admin) external {
        admin = _admin; initialized = true;
    }
}