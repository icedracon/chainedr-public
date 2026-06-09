// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title VulnerableVault — Pre-7702 pattern: tx.origin == msg.sender as EOA gate
/// @notice This pattern was safe pre-Pectra. Post-EIP-7702, a delegated EOA
///         satisfies tx.origin == msg.sender while executing arbitrary contract logic.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "contracts not allowed");
        _;
    }

    function deposit() external payable onlyEOA {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external onlyEOA {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }
}
