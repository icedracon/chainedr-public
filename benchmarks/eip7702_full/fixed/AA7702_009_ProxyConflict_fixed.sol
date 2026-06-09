// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: immutable delegation target, no proxy pattern
/// @notice AA7702-009 — uses 7702 redelegation for upgrades instead of proxy
contract ImmutableDelegationTarget {
    address public owner;

    constructor() { owner = msg.sender; }

    function executeAs(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }
}
