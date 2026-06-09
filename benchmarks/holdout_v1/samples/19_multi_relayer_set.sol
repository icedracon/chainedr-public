// SPDX-License-Identifier: MIT
// Multi-relayer set with owner-managed add/remove. Account remains
// usable if any relayer in the set is reachable. AA7702-019 must NOT
// fire here.
pragma solidity ^0.8.20;

contract MultiRelayerExecutor {
    address private _owner;
    mapping(address => bool) public relayers;

    modifier onlyOwner() { require(msg.sender == _owner, "not owner"); _; }
    modifier onlyRelayer() { require(relayers[msg.sender], "not relayer"); _; }

    constructor(address[] memory initial) {
        _owner = msg.sender;
        for (uint256 i = 0; i < initial.length; i++) relayers[initial[i]] = true;
    }

    function addRelayer(address r) external onlyOwner { relayers[r] = true; }
    function removeRelayer(address r) external onlyOwner { relayers[r] = false; }

    function execute(bytes calldata) external onlyRelayer {}
}
