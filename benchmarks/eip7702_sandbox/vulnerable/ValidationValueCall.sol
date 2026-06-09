// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
}

contract ValidationValueCall {
    address public entryPoint;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        payable(userOp.sender).call{value: 1 wei}("");
        return ("", 0);
    }
}
