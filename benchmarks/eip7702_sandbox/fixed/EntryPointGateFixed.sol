// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    bytes signature;
}

contract EntryPointGateFixed {
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external view onlyEntryPoint returns (uint256 validationData) {
        require(userOp.sender == address(this), "wrong sender");
        require(userOp.signature.length > 0, "missing signature");
        require(userOpHash != bytes32(0), "missing context");
        return 0;
    }
}
