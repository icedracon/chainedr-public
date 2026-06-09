// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    bytes signature;
    address[] authorizationList;
}

contract MinimalSafeAccount {
    address public owner;
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external view onlyEntryPoint returns (uint256 validationData) {
        require(userOp.sender == address(this), "wrong sender");
        require(userOp.signature.length == 65, "bad signature");
        require(userOpHash != bytes32(0), "missing context");
        return owner == address(0) ? 1 : 0;
    }

    function simulateValidation(UserOperation calldata userOp) external pure {
        require(userOp.authorizationList.length == 1, "one EIP-7702 auth tuple");
    }
}
