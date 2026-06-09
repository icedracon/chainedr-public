// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Benign multisig — no EIP-7702 patterns
contract SimpleMultisig {
    address[] public signers;
    uint256 public threshold;
    mapping(bytes32 => uint256) public confirmations;

    constructor(address[] memory _signers, uint256 _threshold) {
        signers = _signers;
        threshold = _threshold;
    }

    function confirm(bytes32 txHash) external {
        bool isSigner = false;
        for (uint i = 0; i < signers.length; i++) {
            if (signers[i] == msg.sender) { isSigner = true; break; }
        }
        require(isSigner, "Not signer");
        confirmations[txHash]++;
    }

    function executeIfReady(bytes32 txHash, address to, bytes calldata data) external {
        require(confirmations[txHash] >= threshold, "Not enough");
        (bool ok,) = to.call(data);
        require(ok);
    }
}
