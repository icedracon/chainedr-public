// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: delegation with revocation mechanism
/// @notice AA7702-005 — users can revoke delegation
contract RevocableDelegation {
    address public delegationTarget;
    address public owner;

    constructor(address _target) {
        delegationTarget = _target;
        owner = msg.sender;
    }

    function setDelegation(address _target) external {
        require(msg.sender == owner, "Not owner");
        delegationTarget = _target;
    }

    function revokeDelegation() external {
        require(msg.sender == owner, "Not owner");
        delegationTarget = address(0);
    }

    function execute(bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        require(delegationTarget != address(0), "No delegation");
        (bool ok,) = delegationTarget.delegatecall(data);
        require(ok, "Execution failed");
    }
}
