// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    bytes signature;
}

contract MissingEntryPointGate {
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external returns (uint256 validationData) {
        require(userOpHash != bytes32(0), "missing context");
        return userOp.signature.length == 65 ? 0 : 1;
    }
}
