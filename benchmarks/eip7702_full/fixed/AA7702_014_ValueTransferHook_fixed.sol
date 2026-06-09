// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: CEI pattern — state updated before transfer
/// @notice AA7702-014 — safe against delegated EOA receive() callbacks
contract SecureValueTransfer {
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "Reentrancy");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function sendReward(address payable recipient, uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        recipient.transfer(amount);
    }
}
