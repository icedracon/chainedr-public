// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ProxyDelegation {
    bytes32 private constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    function upgradeTo(address newImpl) external {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly { sstore(slot, newImpl) }
    }
    fallback() external payable {
        bytes32 slot = _IMPLEMENTATION_SLOT; address impl;
        assembly { impl := sload(slot) }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}