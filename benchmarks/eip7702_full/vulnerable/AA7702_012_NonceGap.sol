// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: meta-tx nonce gap with delegation nonce
/// @notice AA7702-012 — replay_boundary bypass
contract NonceGapExploit {
    mapping(address => uint256) public metaTxNonces;

    function executeMetaTransaction(
        address from, address to, bytes calldata data,
        uint256 nonce, bytes calldata signature
    ) external {
        require(nonce == metaTxNonces[from], "Invalid nonce");
        bytes32 hash = keccak256(abi.encode(from, to, data, nonce));
        require(_verify(hash, signature, from), "Bad sig");
        metaTxNonces[from]++;
        (bool ok,) = to.call(data);
        require(ok);
    }

    function _verify(bytes32, bytes calldata, address) internal pure returns (bool) {
        return true;
    }
}
