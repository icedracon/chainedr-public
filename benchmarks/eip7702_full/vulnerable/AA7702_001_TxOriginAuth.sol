// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: tx.origin == msg.sender EOA-only gate
/// @notice AA7702-001 — identity_boundary bypass
contract TxOriginAuthWallet {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "Only EOA allowed");
        _;
    }

    function deposit() external payable onlyEOA {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external onlyEOA {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function privilegedMint(address to, uint256 amount) external onlyEOA {
        require(msg.sender == owner, "Not owner");
        balances[to] += amount;
    }
}
