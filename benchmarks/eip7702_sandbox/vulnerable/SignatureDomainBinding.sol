// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct PackedUserOperation {
    address sender;
    bytes signature;
}

library ECDSA {
    function recover(bytes32, bytes memory) internal pure returns (address) {
        return address(0x1234);
    }
}

contract SignatureDomainBinding {
    address public entryPoint;
    address public owner;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256
    ) external onlyEntryPoint returns (uint256 validationData) {
        bytes32 partialHash = keccak256(abi.encode(userOp.sender));
        address signer = ECDSA.recover(partialHash, userOp.signature);
        require(signer == owner, "bad signature");
        return 0;
    }
}
