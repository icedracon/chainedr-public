// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    address paymaster;
    bytes authorization;
}

contract DelegatedNonSenderEntity {
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256
    ) external view onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        require(userOp.authorization.length > 0, "EIP-7702 delegated paymaster required");
        require(userOp.paymaster != address(0), "missing paymaster");
        return ("", 0);
    }
}
