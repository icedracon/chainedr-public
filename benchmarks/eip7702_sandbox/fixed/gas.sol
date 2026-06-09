// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract StorageFixed {
    bytes32 private constant STORAGE_SLOT = keccak256("chainedr.storage");
    struct Data { uint value; }
    function _getStorage() private pure returns (Data storage ds) {
        bytes32 slot = STORAGE_SLOT; assembly { ds.slot := slot }
    }
    function setValue(uint v) external { _getStorage().value = v; }
    function initialize() external { _getStorage().value = 0; }
}