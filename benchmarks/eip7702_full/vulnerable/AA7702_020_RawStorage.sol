// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: raw storage without ERC-7201 namespace
/// @notice AA7702-020 — storage_boundary bypass
contract DelegateAccount {
    address public owner;
    uint256 public nonce;
    address public guardian;

    constructor() { owner = msg.sender; }

    function execute(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        nonce++;
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }

    receive() external payable {}
}
