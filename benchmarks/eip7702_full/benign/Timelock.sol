// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Benign timelock — no EIP-7702 patterns
contract Timelock {
    uint256 public constant DELAY = 2 days;
    address public admin;
    mapping(bytes32 => uint256) public scheduled;

    constructor() { admin = msg.sender; }

    function schedule(bytes32 opHash) external {
        require(msg.sender == admin, "Not admin");
        scheduled[opHash] = block.timestamp + DELAY;
    }

    function execute(bytes32 opHash, address to, bytes calldata data) external {
        require(scheduled[opHash] != 0 && block.timestamp >= scheduled[opHash], "Not ready");
        delete scheduled[opHash];
        (bool ok,) = to.call(data);
        require(ok);
    }
}
