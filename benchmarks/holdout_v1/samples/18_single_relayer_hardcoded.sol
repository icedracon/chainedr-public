// SPDX-License-Identifier: MIT
// Hardcoded single relayer with no fallback path. Under EIP-7702 this
// means account liveness depends on one off-chain operator. AA7702-019
// should fire.
pragma solidity ^0.8.20;

contract SingleRelayerExecutor {
    address public constant RELAYER = 0x000000000000000000000000000000000000abCD;

    function execute(bytes calldata) external {
        require(msg.sender == RELAYER, "not relayer");
        // ... single relayer path, no alternative
    }
}
