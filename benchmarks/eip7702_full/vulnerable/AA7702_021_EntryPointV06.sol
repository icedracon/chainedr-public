// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: hardcoded EntryPoint v0.6 address
/// @notice AA7702-021 — validation_boundary bypass
contract EntryPointV06Account {
    // Hardcoded v0.6 EntryPoint — incompatible with v0.7+
    address public constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address public owner;

    constructor() { owner = msg.sender; }

    function validateUserOp(
        bytes calldata userOp, bytes32 userOpHash, uint256 missingFunds
    ) external returns (uint256) {
        require(msg.sender == ENTRY_POINT, "Not EntryPoint");
        // v0.6 validation logic — doesn't handle v0.7 changes
        return 0;
    }

    function execute(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == ENTRY_POINT || msg.sender == owner, "Unauthorized");
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }
}
