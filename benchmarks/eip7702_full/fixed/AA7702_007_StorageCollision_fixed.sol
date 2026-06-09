// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: uses ERC-7201 namespaced storage
/// @notice AA7702-007 — prevents storage collision on redelegation
contract NamespacedDelegationTarget {
    bytes32 private constant _STORAGE_SLOT =
        keccak256("eip7201:namespaced.delegation.v1");

    function _getOwner() private view returns (address o) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { o := sload(slot) }
    }

    function _setOwner(address o) private {
        bytes32 slot = _STORAGE_SLOT;
        assembly { sstore(slot, o) }
    }

    function initialize(address _owner) external {
        require(_getOwner() == address(0), "Already set");
        _setOwner(_owner);
    }

    function execute(address to, bytes calldata data) external {
        require(msg.sender == _getOwner(), "Not owner");
        (bool ok,) = to.call(data);
        require(ok);
    }
}
