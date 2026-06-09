// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
}

contract ValidationValueCallFixed {
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external view onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        require(userOp.sender != address(0), "missing sender");
        require(userOpHash != bytes32(0), "missing context");
        require(maxCost > 0, "missing gas budget");
        return ("", 0);
    }
}
