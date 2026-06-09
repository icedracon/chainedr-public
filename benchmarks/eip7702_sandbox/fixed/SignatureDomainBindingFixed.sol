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

contract SignatureDomainBindingFixed {
    address public entryPoint;
    address public owner;

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "not EntryPoint");
        _;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external view onlyEntryPoint returns (uint256 validationData) {
        require(userOpHash != bytes32(0), "missing EntryPoint domain");
        bytes32 digest = keccak256(abi.encode(userOpHash, userOp.sender, address(this)));
        address signer = ECDSA.recover(digest, userOp.signature);
        require(signer == owner, "bad signature");
        return 0;
    }
}
