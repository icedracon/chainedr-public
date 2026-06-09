// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: removed tx.origin == msg.sender, uses access control instead
/// @notice AA7702-001 — properly handles post-7702 world
contract SecureAuth {
    mapping(address => bool) public authorized;
    address public admin;

    constructor() { admin = msg.sender; }

    modifier onlyAuthorized() {
        require(authorized[msg.sender] || msg.sender == admin, "Not authorized");
        _;
    }

    function authorize(address account) external {
        require(msg.sender == admin, "Not admin");
        authorized[account] = true;
    }

    function protectedAction() external onlyAuthorized {
        // No tx.origin check — uses explicit allowlist
    }
}
