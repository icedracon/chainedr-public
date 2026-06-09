// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    uint256 preVerificationGas;
    address[] authorizationList;
}

contract PreVerificationGasUnderaccounted {
    function simulateValidation(UserOperation calldata userOp) external {
        require(userOp.authorizationList.length == 1, "one EIP-7702 authorization");
        uint256 gasBudget = userOp.preVerificationGas;
        require(gasBudget > 21000, "gas too low");
    }
}
