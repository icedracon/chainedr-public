// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct UserOperation {
    address sender;
    address delegate;
    bytes authorization;
}

contract SameSenderDelegateConsistencyFixed {
    mapping(address => address) public senderToDelegate;

    function handleOps(UserOperation[] calldata ops) external {
        for (uint256 i = 0; i < ops.length; i++) {
            require(ops[i].authorization.length > 0, "missing EIP-7702 authorization");

            address previous = senderToDelegate[ops[i].sender];
            bool sameDelegate = previous == address(0) || previous == ops[i].delegate;
            require(sameDelegate, "delegate mismatch");
        }
    }
}
