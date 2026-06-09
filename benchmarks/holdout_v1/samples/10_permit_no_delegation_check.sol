// SPDX-License-Identifier: MIT
// ERC-20 permit with no delegation-aware check. AA7702-010 should fire
// because a delegated EOA can auto-sign approvals via its delegation
// code path.
pragma solidity ^0.8.20;

contract MiniPermitToken {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            bytes32(0),
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
        ));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner && signer != address(0), "bad sig");
        allowance[owner][spender] = value;
    }
}
