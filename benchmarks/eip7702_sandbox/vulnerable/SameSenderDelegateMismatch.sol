// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address delegate;
    bytes authorization;
}

contract SameSenderDelegateMismatch {
    function handleOps(UserOperation[] calldata ops) external {
        for (uint256 i = 0; i < ops.length; i++) {
            require(ops[i].authorization.length > 0, "missing 7702 authorization");
        }
    }
}
