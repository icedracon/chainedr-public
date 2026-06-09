// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: delegation target with selfdestruct
/// @notice AA7702-015 — code_boundary bypass
contract DelegationSelfDestruct {
    address public owner;

    constructor() { owner = msg.sender; }

    function executeAs(address to, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = to.call(data);
        require(ok);
    }

    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }
}
