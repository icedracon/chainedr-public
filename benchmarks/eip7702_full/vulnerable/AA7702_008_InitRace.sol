// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: initialization race in delegated account
/// @notice AA7702-008 — storage_boundary bypass
contract DelegationAccount {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }

    function executeAs(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }

    receive() external payable {}
}
