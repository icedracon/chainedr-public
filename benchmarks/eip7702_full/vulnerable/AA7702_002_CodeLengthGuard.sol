// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: code.length EOA check bypass
/// @notice AA7702-002 — code_boundary bypass
contract CodeLengthGuard {
    mapping(address => uint256) public stakes;

    function stakeForEOA() external payable {
        require(msg.sender.code.length == 0, "Contracts not allowed");
        stakes[msg.sender] += msg.value;
    }

    function claimReward() external {
        require(msg.sender.code.length == 0, "EOA only");
        uint256 reward = stakes[msg.sender] / 10;
        stakes[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }
}
