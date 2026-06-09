// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Benign merkle airdrop with pull pattern
contract MerkleAirdrop {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    mapping(address => uint256) public claimable;

    constructor(bytes32 _root) { merkleRoot = _root; }

    function claim(bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "Already claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(_verify(proof, merkleRoot, leaf), "Invalid proof");
        claimed[msg.sender] = true;
        claimable[msg.sender] = 1 ether;
    }

    function withdraw() external {
        uint256 amount = claimable[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        claimable[msg.sender] = 0;
    }

    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 hash = leaf;
        for (uint i = 0; i < proof.length; i++) {
            hash = hash < proof[i]
                ? keccak256(abi.encodePacked(hash, proof[i]))
                : keccak256(abi.encodePacked(proof[i], hash));
        }
        return hash == root;
    }

    receive() external payable {}
}
