// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: value transfer to delegated EOA triggers code
/// @notice AA7702-014 — call_boundary bypass
contract ValueTransferHook {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function sendReward(address payable recipient, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        recipient.transfer(amount);
        balances[msg.sender] -= amount;
    }
}
