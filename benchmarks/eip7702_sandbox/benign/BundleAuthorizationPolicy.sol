// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address delegate;
    address[] authorizationList;
}

contract BundleAuthorizationPolicy {
    uint256 internal constant PER_EMPTY_ACCOUNT_COST = 25_000;
    mapping(address => address) public delegateOfSender;

    function simulateValidation(UserOperation calldata userOp, uint256 preVerificationGas) external view {
        require(userOp.sender != address(0), "missing sender");
        require(userOp.authorizationList.length == 1, "one EIP-7702 auth tuple");
        require(delegateOfSender[userOp.sender] == userOp.delegate, "delegate mismatch");
        require(preVerificationGas >= 21_000 + PER_EMPTY_ACCOUNT_COST, "gas too low");
    }
}
