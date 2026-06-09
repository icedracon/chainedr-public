// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: no code.length EOA assumption — uses allowlist instead
/// @notice AA7702-002 — properly handles delegated EOAs
contract SecureStaking {
    mapping(address => uint256) public stakes;
    mapping(address => bool) public allowedStakers;
    address public admin;

    constructor() { admin = msg.sender; }

    function setAllowed(address staker, bool allowed) external {
        require(msg.sender == admin, "Not admin");
        allowedStakers[staker] = allowed;
    }

    function stake() external payable {
        require(allowedStakers[msg.sender], "Not allowed");
        stakes[msg.sender] += msg.value;
    }

    function claimReward() external {
        uint256 reward = stakes[msg.sender] / 10;
        stakes[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
    }
}
