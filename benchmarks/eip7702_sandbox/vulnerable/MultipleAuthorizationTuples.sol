// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address[] authorizationList;
}

contract MultipleAuthorizationTuples {
    function simulateValidation(UserOperation calldata userOp) external {
        require(userOp.authorizationList.length > 0, "missing EIP-7702 auth");
    }
}
