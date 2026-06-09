// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes signature;
}

contract EntryPointGatedAccount {
    address public owner;
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
        require(userOp.nonce > 0, "missing nonce");
        require(userOpHash != bytes32(0), "missing context");
        require(userOp.signature.length == 65, "bad signature");
        return owner == address(0) ? 1 : 0;
    }
}
