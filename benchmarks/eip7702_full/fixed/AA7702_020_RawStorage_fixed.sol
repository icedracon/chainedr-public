// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: ERC-7201 namespaced storage for delegation target
/// @notice AA7702-020 — prevents storage collision on redelegation
contract DelegateAccountNamespaced {
    bytes32 private constant STORAGE_LOCATION =
        keccak256("eip7201:delegate.account.storage.v1");

    struct DelegateStorage {
        address owner;
        uint256 nonce;
        address guardian;
    }

    function _storage() private pure returns (DelegateStorage storage s) {
        bytes32 slot = STORAGE_LOCATION;
        assembly { s.slot := slot }
    }

    function execute(address to, uint256 value, bytes calldata data) external {
        DelegateStorage storage s = _storage();
        require(msg.sender == s.owner, "Not owner");
        s.nonce++;
        (bool ok,) = to.call{value: value}(data);
        require(ok);
    }

    receive() external payable {}
}
