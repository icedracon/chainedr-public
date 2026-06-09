// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Fixed: bitmap nonce tolerant of gaps
/// @notice AA7702-012 — separate nonce domain from 7702 auth nonce
contract GapTolerantMetaTx {
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    function executeMetaTransaction(
        address from, address to, bytes calldata data,
        uint256 nonce, bytes calldata signature
    ) external {
        uint256 wordIndex = nonce / 256;
        uint256 bitIndex = nonce % 256;
        uint256 word = nonceBitmap[from][wordIndex];
        uint256 mask = 1 << bitIndex;
        require(word & mask == 0, "Nonce already used");
        nonceBitmap[from][wordIndex] = word | mask;
        bytes32 hash = keccak256(abi.encode(from, to, data, nonce));
        require(_verify(hash, signature, from), "Bad sig");
        (bool ok,) = to.call(data);
        require(ok);
    }

    function _verify(bytes32, bytes calldata, address) internal pure returns (bool) {
        return true;
    }
}
