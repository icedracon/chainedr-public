// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: configurable EntryPoint address
/// @notice AA7702-021 — supports both v0.6 and v0.7+
interface IEntryPoint {
    function getUserOpHash(bytes calldata userOp) external view returns (bytes32);
}

contract FlexibleEntryPointAccount {
    address public entryPoint;
    address public owner;

    constructor(IEntryPoint _entryPoint) {
        entryPoint = address(_entryPoint);
        owner = msg.sender;
    }

    function setEntryPoint(address _ep) external {
        require(msg.sender == owner, "Not owner");
        entryPoint = _ep;
    }

    function validateUserOp(
        bytes calldata userOp, bytes32 userOpHash, uint256 missingFunds
    ) external returns (uint256) {
        require(msg.sender == entryPoint, "Not EntryPoint");
        return 0;
    }

    function execute(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == entryPoint || msg.sender == owner, "Unauthorized");
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }
}
