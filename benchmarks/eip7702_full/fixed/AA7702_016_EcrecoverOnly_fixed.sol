// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: signature verification with EIP-1271 fallback
/// @notice AA7702-016 — supports both EOAs and delegated EOAs
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4);
}

contract SignatureCheckerCompat {
    function isValidSignatureNow(
        address signer, bytes32 hash, bytes calldata signature
    ) public view returns (bool) {
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(signature, (uint8, bytes32, bytes32));
        address recovered = ecrecover(hash, v, r, s);
        if (recovered == signer) return true;
        try IERC1271(signer).isValidSignature(hash, signature) returns (bytes4 result) {
            return result == 0x1626ba7e;
        } catch {
            return false;
        }
    }
}
