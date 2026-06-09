// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: initializer with one-time guard
/// @notice AA7702-008 — prevents front-running of init
contract SecureDelegationAccount {
    address public owner;
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "Already initialized");
        _initialized = true;
        _;
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    function executeAs(address to, uint256 value, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }

    receive() external payable {}
}
