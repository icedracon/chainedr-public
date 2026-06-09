// SPDX-License-Identifier: MIT
// ERC-7201 namespaced storage layout — collision-safe across delegation
// target switches. AA7702-007 / AA7702-020 must not fire.
pragma solidity ^0.8.20;

contract Namespaced {
    /// @custom:storage-location erc7201:chainedr.holdout.namespaced
    struct Layout {
        address owner;
        uint256 nonce;
    }

    bytes32 private constant LAYOUT_SLOT =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    function _layout() internal pure returns (Layout storage l) {
        bytes32 slot = LAYOUT_SLOT;
        assembly { l.slot := slot }
    }

    function bump() external {
        _layout().nonce += 1;
    }
}
