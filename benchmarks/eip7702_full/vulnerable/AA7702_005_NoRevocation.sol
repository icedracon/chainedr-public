// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: no delegation revocation path
/// @notice AA7702-005 — revocation_boundary bypass
contract IrrevocableDelegation {
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

    function execute(bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = delegationTarget.delegatecall(data);
        require(ok, "Execution failed");
    }
}
