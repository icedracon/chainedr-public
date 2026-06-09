// SPDX-License-Identifier: MIT
// Clean UUPS-style upgrade gate: _authorizeUpgrade is gated by onlyOwner.
// The ERC-1967 proxy slot read inside _authorizeUpgrade is the standard
// upgrade mechanic, not an attacker-reachable path. AA7702-009 must not fire.
pragma solidity ^0.8.20;

contract UUPSCorrect {
    address private _owner;
    bytes32 private constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    constructor() { _owner = msg.sender; }

    function _authorizeUpgrade(address) internal view onlyOwner {}

    function upgradeTo(address newImpl) external {
        _authorizeUpgrade(newImpl);
        assembly { sstore(_IMPLEMENTATION_SLOT, newImpl) }
    }
}
