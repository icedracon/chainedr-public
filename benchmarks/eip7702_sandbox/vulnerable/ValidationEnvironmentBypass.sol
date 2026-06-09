// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
}

contract ValidationEnvironmentBypass {
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256
    ) external onlyEntryPoint returns (uint256 validationData) {
        require(tx.origin == userOp.sender, "delegated EOA only");
        require(block.timestamp < 2000000000, "expired");
        return 0;
    }
}
