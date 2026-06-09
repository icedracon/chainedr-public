// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address[] authorizationList;
}

contract MultipleAuthorizationTuplesFixed {
    function simulateValidation(UserOperation calldata userOp) external pure {
        require(userOp.sender != address(0), "missing sender");
        require(userOp.authorizationList.length == 1, "one EIP-7702 authorization");
    }
}
