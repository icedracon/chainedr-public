// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: signature check with EIP-1271 for delegation awareness
/// @notice AA7702-010 — supports delegated EOA signers
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

contract DelegationAwareApproval {
    mapping(address => mapping(address => uint256)) public allowance;

    function approveWithSignature(
        address signer, address spender, uint256 value,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(signer, spender, value));
        address recovered = ecrecover(digest, v, r, s);
        if (recovered != signer) {
            bytes4 result = IERC1271(signer).isValidSignature(
                digest, abi.encodePacked(r, s, v)
            );
            require(result == 0x1626ba7e, "Invalid sig");
        }
        allowance[signer][spender] = value;
    }
}
