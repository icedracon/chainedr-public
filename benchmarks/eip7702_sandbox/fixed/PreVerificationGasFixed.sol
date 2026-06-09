// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    uint256 preVerificationGas;
    address[] authorizationList;
}

contract PreVerificationGasFixed {
    uint256 internal constant PER_EMPTY_ACCOUNT_COST = 25_000;

    function simulateValidation(UserOperation calldata userOp) external pure {
        require(userOp.authorizationList.length == 1, "one EIP-7702 authorization");
        uint256 gasBudget = userOp.preVerificationGas;
        uint256 requiredBudget = 21_000 + PER_EMPTY_ACCOUNT_COST * userOp.authorizationList.length;
        require(gasBudget >= requiredBudget, "gas too low");
        require(userOp.sender != address(0), "missing sender");
    }
}
