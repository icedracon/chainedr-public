// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: gas-limited relay with budget
/// @notice AA7702-013 — prevents delegation gas griefing
contract GasLimitedRelay {
    uint256 public constant MAX_EXEC_GAS = 500_000;
    mapping(address => uint256) public gasBudget;
    address public paymaster;

    constructor() { paymaster = msg.sender; }

    function sponsoredExec(address account, bytes calldata data) external {
        require(gasleft() > MAX_EXEC_GAS + 50_000, "Insufficient gas");
        uint256 gasBefore = gasleft();
        (bool ok,) = account.call{gas: MAX_EXEC_GAS}(data);
        uint256 gasUsed = gasBefore - gasleft();
        gasBudget[account] += gasUsed;
    }
}
