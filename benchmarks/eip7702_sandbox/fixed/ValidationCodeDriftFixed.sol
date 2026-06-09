// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
}

contract ValidationCodeDriftFixed {
    address public entryPoint;
    bytes32 public trustedCodeHash;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external view onlyEntryPoint returns (uint256 validationData) {
        require(userOpHash != bytes32(0), "missing context");
        bytes32 codehash = userOp.sender.codehash;
        require(codehash == trustedCodeHash, "unexpected codehash");
        return 0;
    }
}
