// SPDX-License-Identifier: MIT
// EIP-7702 SmartAccount delegation target with raw, non-namespaced
// storage. On redelegation the next target's layout collides with
// these slots. AA7702-020 should fire.
pragma solidity ^0.8.20;

contract NaiveSmartAccountStorage {
    address public owner;
    uint256 public nonce;
    mapping(address => bool) public approved;

    function approve(address who) external {
        require(msg.sender == owner, "not owner");
        approved[who] = true;
    }
}
