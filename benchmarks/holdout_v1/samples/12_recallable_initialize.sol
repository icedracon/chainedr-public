// SPDX-License-Identifier: MIT
// Initializer without an init-flag guard. Under EIP-7702 every delegation
// target call lands in a fresh EOA-storage context; this initialize() can
// be called by anyone and re-points the owner. AA7702-008 should fire.
pragma solidity ^0.8.20;

contract NaiveSmartAccount {
    address public owner;

    function initialize(address newOwner) external {
        owner = newOwner;
    }
}
