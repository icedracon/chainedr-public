// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract PermitFixed {
    mapping(address => bool) public delegationAware;

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(owner.code.length == 0 || delegationAware[owner], "delegated EOA not allowed");
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), value, spender, deadline));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner);
    }
}
