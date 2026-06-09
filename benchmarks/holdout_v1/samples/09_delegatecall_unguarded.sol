// SPDX-License-Identifier: MIT
// Delegation-target shape with an unguarded delegatecall. Should fire
// AA7702-006 — anyone can pick the impl, which under 7702 collapses
// the kernel context.
pragma solidity ^0.8.20;

// Marker comment so the static delegation-target heuristic classifies
// this file: "EIP7702 SmartAccount delegation target".

contract OpenDelegate {
    receive() external payable {}

    function run(address impl, bytes calldata data) external {
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "exec failed");
    }
}
