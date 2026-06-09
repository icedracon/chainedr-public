// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: uses call() instead of delegatecall in delegation target
/// @notice AA7702-006 — no nested context confusion
contract SecureAccountDelegation {
    address public owner;
    address public implementation;

    constructor() { owner = msg.sender; }

    function setImplementation(address _impl) external {
        require(msg.sender == owner, "Not owner");
        implementation = _impl;
    }

    function delegatedExec(bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = implementation.call(data);
        require(ok, "call failed");
    }
}
