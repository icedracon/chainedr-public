// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: ERC-1967 proxy conflict with EIP-7702 delegation
/// @notice AA7702-009 — storage_boundary bypass
contract ERC1967DelegationProxy {
    // ERC-1967 implementation slot
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    address public owner;

    constructor(address _impl) {
        owner = msg.sender;
        _setImplementation(_impl);
    }

    function upgradeTo(address newImpl) external {
        require(msg.sender == owner, "Not owner");
        _setImplementation(newImpl);
    }

    function _setImplementation(address impl) internal {
        assembly { sstore(_IMPLEMENTATION_SLOT, impl) }
    }

    fallback() external payable {
        address impl;
        assembly { impl := sload(_IMPLEMENTATION_SLOT) }
        (bool ok,) = impl.delegatecall(msg.data);
        require(ok);
    }

    receive() external payable {}
}
