// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;
contract EntryPointVuln {
    address constant ENTRYPOINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    function execute() external {
        ENTRYPOINT.call(abi.encodeWithSignature("handleOps()"));
    }
}