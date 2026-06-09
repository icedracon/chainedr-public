// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable: permit() with ecrecover only, no EIP-1271
/// @notice AA7702-010 — validation_boundary bypass
contract PermitVulnerableToken {
    string public name = "PermitToken";
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)), block.chainid, address(this)
        ));
    }

    function permit(
        address owner, address spender, uint256 value,
        uint256 deadline, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Expired");
        bytes32 hash = keccak256(abi.encodePacked(
            "\x19\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(owner, spender, value, nonces[owner]++, deadline))
        ));
        // ecrecover only — no EIP-1271 isValidSignature fallback
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        allowance[owner][spender] = value;
    }
}
