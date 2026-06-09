// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: gas griefing in sponsored execution
/// @notice AA7702-013 — gas_boundary bypass
contract GasGriefingRelay {
    address public relayer;
    mapping(address => uint256) public balances;

    constructor() { relayer = msg.sender; }

    function sponsoredExecute(
        address account, address target, bytes calldata data
    ) external {
        require(msg.sender == relayer, "Not relayer");
        // No gas limit — delegated code can consume all sponsor gas
        (bool ok,) = target.call(data);
        require(ok, "Execution failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
