// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: delegatecall context escape in delegation target
/// @notice AA7702-006 — call_boundary bypass
contract AccountDelegation {
    address public owner;
    address public implementation;

    constructor() { owner = msg.sender; }

    function setImplementation(address _impl) external {
        require(msg.sender == owner, "Not owner");
        implementation = _impl;
    }

    function delegatedExec(bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
