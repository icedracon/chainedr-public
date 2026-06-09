// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract PermitBypass {
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(value, spender, deadline));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner);
    }
}