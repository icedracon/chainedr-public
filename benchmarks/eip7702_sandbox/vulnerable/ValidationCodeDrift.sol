// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
}

contract ValidationCodeDrift {
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256
    ) external view onlyEntryPoint returns (uint256 validationData) {
        require(userOp.sender.code.length > 0, "missing delegated code");
        return 0;
    }
}
